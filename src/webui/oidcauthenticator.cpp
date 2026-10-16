/*
 * Bittorrent Client using Qt and libtorrent.
 * Copyright (C) 2026  qBittorrent contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give permission to
 * link this program with the OpenSSL project's "OpenSSL" library (or with
 * modified versions of it that use the same license as the "OpenSSL" library),
 * and distribute the linked executables. You must obey the GNU General Public
 * License in all respects for all of the code used other than "OpenSSL".  If you
 * modify file(s), you may extend this exception to your version of the file(s),
 * but you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 */

#include "oidcauthenticator.h"

#include <QCryptographicHash>
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QThread>
#include <QTimer>
#include <QUrlQuery>

#include "base/logger.h"
#include "base/utils/random.h"

using namespace Qt::Literals::StringLiterals;

class OidcHttpWorker final : public QObject
{
    Q_OBJECT

public:
    explicit OidcHttpWorker(QObject *parent = nullptr)
        : QObject(parent)
    {
    }

    struct HttpResult
    {
        QByteArray data;
        int statusCode = 0;
        QString error;
    };

    HttpResult executeGet(const QUrl &url, const QMap<QString, QString> &headers, const int timeoutMs)
    {
        ensureNam();
        QNetworkRequest request(url);
        for (auto it = headers.cbegin(); it != headers.cend(); ++it)
            request.setRawHeader(it.key().toUtf8(), it.value().toUtf8());

        QNetworkReply *reply = m_nam->get(request);
        return waitForReply(reply, timeoutMs);
    }

    HttpResult executePost(const QUrl &url, const QByteArray &postData, const QMap<QString, QString> &headers, const int timeoutMs)
    {
        ensureNam();
        QNetworkRequest request(url);
        for (auto it = headers.cbegin(); it != headers.cend(); ++it)
            request.setRawHeader(it.key().toUtf8(), it.value().toUtf8());

        QNetworkReply *reply = m_nam->post(request, postData);
        return waitForReply(reply, timeoutMs);
    }

private:
    void ensureNam()
    {
        if (!m_nam)
            m_nam = new QNetworkAccessManager(this);
    }

    HttpResult waitForReply(QNetworkReply *reply, const int timeoutMs)
    {
        HttpResult result;
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        bool timedOut = false;

        connect(&timer, &QTimer::timeout, &loop, [&]()
        {
            timedOut = true;
            reply->abort();
            loop.quit();
        });
        connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);

        timer.start(timeoutMs);
        loop.exec();

        timer.stop();
        disconnect(reply, nullptr, nullptr, nullptr);

        if (timedOut)
        {
            result.statusCode = 408;
            result.error = u"Network request timed out"_s;
        }
        else if (reply->error() != QNetworkReply::NoError)
        {
            const QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
            result.statusCode = statusCode.isValid() ? statusCode.toInt() : 500;
            result.error = reply->errorString();
            result.data = reply->readAll();
        }
        else
        {
            const QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
            result.statusCode = statusCode.isValid() ? statusCode.toInt() : 200;
            result.data = reply->readAll();
        }

        reply->deleteLater();
        return result;
    }

    QNetworkAccessManager *m_nam = nullptr;
};

OidcAuthenticator::OidcAuthenticator(QObject *parent)
    : QObject(parent)
{
    initFromEnvironment();
}

OidcAuthenticator::OidcAuthenticator(const Oidc::Config &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
{
    while (m_config.issuerUrl.endsWith(u'/'))
        m_config.issuerUrl.chop(1);
}

OidcAuthenticator::~OidcAuthenticator()
{
    stopWorkerThread();
}

void OidcAuthenticator::initFromEnvironment()
{
    m_config.issuerUrl = qEnvironmentVariable("OIDC_ISSUER_URL").trimmed();
    while (m_config.issuerUrl.endsWith(u'/'))
        m_config.issuerUrl.chop(1);

    m_config.clientId = qEnvironmentVariable("OIDC_CLIENT_ID").trimmed();
    m_config.clientSecret = qEnvironmentVariable("OIDC_CLIENT_SECRET").trimmed();
    m_config.redirectUri = qEnvironmentVariable("OIDC_REDIRECT_URI").trimmed();

    const QString scopes = qEnvironmentVariable("OIDC_SCOPES").trimmed();
    if (!scopes.isEmpty())
        m_config.scopes = scopes;

    m_config.adminGroup = qEnvironmentVariable("OIDC_ADMIN_GROUP").trimmed();

    const QString displayName = qEnvironmentVariable("OIDC_DISPLAY_NAME").trimmed();
    if (!displayName.isEmpty())
        m_config.displayName = displayName;
}

void OidcAuthenticator::startWorkerThread()
{
    if (m_workerThread)
        return;

    m_workerThread = new QThread(this);
    m_worker = new OidcHttpWorker();
    m_worker->moveToThread(m_workerThread);
    m_workerThread->start();
}

void OidcAuthenticator::stopWorkerThread()
{
    if (m_workerThread)
    {
        m_workerThread->quit();
        m_workerThread->wait();
        delete m_worker;
        m_worker = nullptr;
        delete m_workerThread;
        m_workerThread = nullptr;
    }
}

bool OidcAuthenticator::isEnabled() const
{
    return !m_config.issuerUrl.isEmpty() && !m_config.clientId.isEmpty();
}

const Oidc::Config &OidcAuthenticator::config() const
{
    return m_config;
}

QString OidcAuthenticator::displayName() const
{
    return m_config.displayName;
}

Oidc::PkcePair OidcAuthenticator::generatePkcePair()
{
    QByteArray randomBytes(32, Qt::Uninitialized);
    auto *words = reinterpret_cast<quint32 *>(randomBytes.data());
    for (int i = 0; i < 8; ++i)
        words[i] = Utils::Random::rand();

    const QString codeVerifier = QString::fromLatin1(
        randomBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));

    const QByteArray hash = QCryptographicHash::hash(codeVerifier.toUtf8(), QCryptographicHash::Sha256);
    const QString codeChallenge = QString::fromLatin1(
        hash.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));

    return {codeVerifier, codeChallenge};
}

QString OidcAuthenticator::generateState()
{
    QByteArray randomBytes(32, Qt::Uninitialized);
    auto *words = reinterpret_cast<quint32 *>(randomBytes.data());
    for (int i = 0; i < 8; ++i)
        words[i] = Utils::Random::rand();

    return QString::fromLatin1(
        randomBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QJsonObject OidcAuthenticator::decodeJwtPayload(const QString &jwt)
{
    const QStringList parts = jwt.split(u'.');
    if (parts.size() < 2)
        return {};

    QByteArray payloadBytes = parts[1].toLatin1();
    while (payloadBytes.size() % 4 != 0)
        payloadBytes.append('=');

    QByteArray jsonBytes = QByteArray::fromBase64(payloadBytes, QByteArray::Base64UrlEncoding);
    if (jsonBytes.isEmpty())
        jsonBytes = QByteArray::fromBase64(payloadBytes);

    const QJsonDocument doc = QJsonDocument::fromJson(jsonBytes);
    return doc.isObject() ? doc.object() : QJsonObject {};
}

bool OidcAuthenticator::verifyAdminGroup(const QJsonObject &claims, const QString &requiredGroup)
{
    const QString target = requiredGroup.trimmed();
    if (target.isEmpty())
        return true;

    auto checkValue = [&](const QJsonValue &val) -> bool
    {
        if (val.isArray())
        {
            const QJsonArray arr = val.toArray();
            for (const auto &item : arr)
            {
                if (item.toString().compare(target, Qt::CaseInsensitive) == 0)
                    return true;
            }
        }
        else if (val.isString())
        {
            const QString s = val.toString();
            if (s.compare(target, Qt::CaseInsensitive) == 0)
                return true;

            const QStringList tokens = s.split(QRegularExpression(u"[,\\s]+"_s), Qt::SkipEmptyParts);
            for (const QString &tok : tokens)
            {
                if (tok.compare(target, Qt::CaseInsensitive) == 0)
                    return true;
            }
        }
        return false;
    };

    if (checkValue(claims.value(u"groups"_s)))
        return true;
    if (checkValue(claims.value(u"roles"_s)))
        return true;
    if (claims.contains(u"realm_access"_s) && claims[u"realm_access"_s].isObject())
    {
        if (checkValue(claims[u"realm_access"_s].toObject().value(u"roles"_s)))
            return true;
    }

    return false;
}

QString OidcAuthenticator::extractUserIdentifier(const QJsonObject &claims)
{
    const QStringList candidates = {
        u"preferred_username"_s,
        u"username"_s,
        u"email"_s,
        u"name"_s,
        u"sub"_s
    };

    for (const auto &field : candidates)
    {
        if (claims.contains(field))
        {
            const QString val = claims.value(field).toString().trimmed();
            if (!val.isEmpty())
                return val;
        }
    }
    return {};
}

void OidcAuthenticator::storePendingState(const QString &state, const QString &codeVerifier, const std::chrono::seconds ttl)
{
    QMutexLocker locker(&m_mutex);
    purgeExpiredStates();

    if (m_pendingStates.size() >= 100)
    {
        auto oldest = m_pendingStates.begin();
        for (auto it = m_pendingStates.begin(); it != m_pendingStates.end(); ++it)
        {
            if (it.value().expiresAt < oldest.value().expiresAt)
                oldest = it;
        }
        if (oldest != m_pendingStates.end())
            m_pendingStates.erase(oldest);
    }

    m_pendingStates.insert(state, {codeVerifier, QDateTime::currentDateTimeUtc().addSecs(ttl.count())});
}

bool OidcAuthenticator::consumeState(const QString &state, QString &codeVerifier)
{
    QMutexLocker locker(&m_mutex);
    purgeExpiredStates();

    const auto it = m_pendingStates.find(state);
    if (it == m_pendingStates.end())
        return false;

    if (it.value().expiresAt < QDateTime::currentDateTimeUtc())
    {
        m_pendingStates.erase(it);
        return false;
    }

    codeVerifier = it.value().codeVerifier;
    m_pendingStates.erase(it);
    return true;
}

int OidcAuthenticator::pendingStatesCount() const
{
    QMutexLocker locker(&m_mutex);
    return m_pendingStates.size();
}

void OidcAuthenticator::purgeExpiredStates()
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (auto it = m_pendingStates.begin(); it != m_pendingStates.end();)
    {
        if (it.value().expiresAt < now)
            it = m_pendingStates.erase(it);
        else
            ++it;
    }
}

bool OidcAuthenticator::loadDiscovery(const int timeoutMs)
{
    if (m_discoveryLoaded)
        return true;

    if (m_config.issuerUrl.isEmpty())
        return false;

    const QUrl discoveryUrl(m_config.issuerUrl + u"/.well-known/openid-configuration"_s);
    int httpCode = 0;
    QString errorMsg;
    const QByteArray data = executeHttpGet(discoveryUrl, {{u"Accept"_s, u"application/json"_s}}, timeoutMs, httpCode, errorMsg);

    if (httpCode != 200 || data.isEmpty())
    {
        LogMsg(u"OIDC: Failed to fetch discovery from %1: %2 (HTTP %3)"_s
            .arg(discoveryUrl.toString(), errorMsg, QString::number(httpCode)), Log::WARNING);
        return false;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject())
    {
        LogMsg(u"OIDC: Invalid discovery JSON response"_s, Log::WARNING);
        return false;
    }

    const QJsonObject obj = doc.object();
    m_authorizationEndpoint = obj.value(u"authorization_endpoint"_s).toString();
    m_tokenEndpoint = obj.value(u"token_endpoint"_s).toString();
    m_userinfoEndpoint = obj.value(u"userinfo_endpoint"_s).toString();

    if (m_authorizationEndpoint.isEmpty() || m_tokenEndpoint.isEmpty())
    {
        LogMsg(u"OIDC: Discovery document missing required endpoints"_s, Log::WARNING);
        return false;
    }

    m_discoveryLoaded = true;
    return true;
}

void OidcAuthenticator::setEndpoints(const QString &authEndpoint, const QString &tokenEndpoint, const QString &userinfoEndpoint)
{
    m_authorizationEndpoint = authEndpoint;
    m_tokenEndpoint = tokenEndpoint;
    m_userinfoEndpoint = userinfoEndpoint;
    m_discoveryLoaded = (!authEndpoint.isEmpty() && !tokenEndpoint.isEmpty());
}

QString OidcAuthenticator::authorizationEndpoint() const
{
    return m_authorizationEndpoint;
}

QString OidcAuthenticator::tokenEndpoint() const
{
    return m_tokenEndpoint;
}

QString OidcAuthenticator::userinfoEndpoint() const
{
    return m_userinfoEndpoint;
}

bool OidcAuthenticator::isDiscoveryLoaded() const
{
    return m_discoveryLoaded;
}

QString OidcAuthenticator::buildAuthorizationUrl(const QString &effectiveRedirectUri)
{
    if (!m_discoveryLoaded && !loadDiscovery())
        return {};

    const QString redirectUri = !m_config.redirectUri.isEmpty() ? m_config.redirectUri : effectiveRedirectUri;
    const Oidc::PkcePair pkce = generatePkcePair();
    const QString state = generateState();

    storePendingState(state, pkce.codeVerifier);

    QUrl url(m_authorizationEndpoint);
    QUrlQuery query(url.query());
    query.addQueryItem(u"response_type"_s, u"code"_s);
    query.addQueryItem(u"client_id"_s, m_config.clientId);
    query.addQueryItem(u"redirect_uri"_s, redirectUri);
    query.addQueryItem(u"scope"_s, m_config.scopes);
    query.addQueryItem(u"state"_s, state);
    query.addQueryItem(u"code_challenge"_s, pkce.codeChallenge);
    query.addQueryItem(u"code_challenge_method"_s, u"S256"_s);

    url.setQuery(query);
    return url.toString();
}

Oidc::TokenResponse OidcAuthenticator::exchangeCodeAndVerify(
    const QString &code, const QString &state, const QString &effectiveRedirectUri, const int timeoutMs)
{
    QString codeVerifier;
    if (!consumeState(state, codeVerifier))
    {
        return {
            .success = false,
            .error = u"Invalid or expired OIDC state parameter"_s
        };
    }

    if (!m_discoveryLoaded && !loadDiscovery(timeoutMs))
    {
        return {
            .success = false,
            .error = u"Failed to load OIDC discovery document"_s
        };
    }

    const QString redirectUri = !m_config.redirectUri.isEmpty() ? m_config.redirectUri : effectiveRedirectUri;

    QUrlQuery postParams;
    postParams.addQueryItem(u"grant_type"_s, u"authorization_code"_s);
    postParams.addQueryItem(u"code"_s, code);
    postParams.addQueryItem(u"redirect_uri"_s, redirectUri);
    postParams.addQueryItem(u"client_id"_s, m_config.clientId);
    if (!m_config.clientSecret.isEmpty())
        postParams.addQueryItem(u"client_secret"_s, m_config.clientSecret);
    postParams.addQueryItem(u"code_verifier"_s, codeVerifier);

    const QByteArray postData = postParams.toString(QUrl::FullyEncoded).toUtf8();
    const QMap<QString, QString> headers = {
        {u"Content-Type"_s, u"application/x-www-form-urlencoded"_s},
        {u"Accept"_s, u"application/json"_s}
    };

    int httpCode = 0;
    QString errorMsg;
    const QByteArray tokenData = executeHttpPost(QUrl(m_tokenEndpoint), postData, headers, timeoutMs, httpCode, errorMsg);

    if (httpCode != 200 || tokenData.isEmpty())
    {
        return {
            .success = false,
            .error = u"Token exchange failed: HTTP %1: %2"_s.arg(QString::number(httpCode), errorMsg)
        };
    }

    const QJsonDocument tokenDoc = QJsonDocument::fromJson(tokenData);
    if (!tokenDoc.isObject())
    {
        return {
            .success = false,
            .error = u"Invalid token response JSON"_s
        };
    }

    const QJsonObject tokenObj = tokenDoc.object();
    if (tokenObj.contains(u"error"_s))
    {
        const QString err = tokenObj.value(u"error_description"_s).toString(tokenObj.value(u"error"_s).toString());
        return {
            .success = false,
            .error = u"Token endpoint error: %1"_s.arg(err)
        };
    }

    const QString accessToken = tokenObj.value(u"access_token"_s).toString();
    const QString idToken = tokenObj.value(u"id_token"_s).toString();

    const QJsonObject idTokenClaims = decodeJwtPayload(idToken);
    QJsonObject userInfoClaims;

    if (!m_userinfoEndpoint.isEmpty() && !accessToken.isEmpty())
    {
        int userInfoCode = 0;
        QString userInfoError;
        const QByteArray userInfoData = executeHttpGet(
            QUrl(m_userinfoEndpoint),
            {{u"Authorization"_s, u"Bearer %1"_s.arg(accessToken)}, {u"Accept"_s, u"application/json"_s}},
            timeoutMs, userInfoCode, userInfoError);

        if (userInfoCode == 200 && !userInfoData.isEmpty())
        {
            const QJsonDocument userDoc = QJsonDocument::fromJson(userInfoData);
            if (userDoc.isObject())
                userInfoClaims = userDoc.object();
        }
    }

    QJsonObject combinedClaims = idTokenClaims;
    for (auto it = userInfoClaims.constBegin(); it != userInfoClaims.constEnd(); ++it)
        combinedClaims.insert(it.key(), it.value());

    const QString username = extractUserIdentifier(combinedClaims);
    if (username.isEmpty())
    {
        return {
            .success = false,
            .error = u"No valid user identity claim found in OIDC token"_s
        };
    }

    if (!m_config.adminGroup.isEmpty())
    {
        if (!verifyAdminGroup(combinedClaims, m_config.adminGroup))
        {
            return {
                .success = false,
                .error = u"User '%1' is not a member of the required admin group '%2'"_s.arg(username, m_config.adminGroup)
            };
        }
    }

    return {
        .success = true,
        .error = {},
        .accessToken = accessToken,
        .idToken = idToken,
        .idTokenPayload = idTokenClaims,
        .userInfo = userInfoClaims,
        .combinedClaims = combinedClaims,
        .username = username
    };
}

QByteArray OidcAuthenticator::executeHttpGet(
    const QUrl &url, const QMap<QString, QString> &headers, const int timeoutMs, int &httpCode, QString &errorMsg)
{
    startWorkerThread();

    OidcHttpWorker::HttpResult result;
    if (QThread::currentThread() == m_workerThread)
    {
        result = m_worker->executeGet(url, headers, timeoutMs);
    }
    else
    {
        QMetaObject::invokeMethod(m_worker, [&]()
        {
            result = m_worker->executeGet(url, headers, timeoutMs);
        }, Qt::BlockingQueuedConnection);
    }

    httpCode = result.statusCode;
    errorMsg = result.error;
    return result.data;
}

QByteArray OidcAuthenticator::executeHttpPost(
    const QUrl &url, const QByteArray &postData, const QMap<QString, QString> &headers, const int timeoutMs, int &httpCode, QString &errorMsg)
{
    startWorkerThread();

    OidcHttpWorker::HttpResult result;
    if (QThread::currentThread() == m_workerThread)
    {
        result = m_worker->executePost(url, postData, headers, timeoutMs);
    }
    else
    {
        QMetaObject::invokeMethod(m_worker, [&]()
        {
            result = m_worker->executePost(url, postData, headers, timeoutMs);
        }, Qt::BlockingQueuedConnection);
    }

    httpCode = result.statusCode;
    errorMsg = result.error;
    return result.data;
}

#include "oidcauthenticator.moc"
