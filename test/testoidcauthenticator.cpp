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

#include <QCryptographicHash>
#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <QUrlQuery>

#include "webui/oidcauthenticator.h"

using namespace Qt::Literals::StringLiterals;

class MockServerWorker : public QObject
{
    Q_OBJECT

public:
    explicit MockServerWorker(QObject *parent = nullptr)
        : QObject(parent)
    {
    }

    quint16 start()
    {
        m_server = new QTcpServer(this);
        connect(m_server, &QTcpServer::newConnection, this, &MockServerWorker::handleConnection);
        if (m_server->listen(QHostAddress::LocalHost, 0))
            return m_server->serverPort();
        return 0;
    }

    void stop()
    {
        if (m_server)
        {
            m_server->close();
            delete m_server;
            m_server = nullptr;
        }
    }

    void setTokenError(const QString &error)
    {
        m_tokenError = error;
    }

    void setUserGroups(const QStringList &groups)
    {
        m_userGroups = groups;
    }

private slots:
    void handleConnection()
    {
        while (m_server && m_server->hasPendingConnections())
        {
            QTcpSocket *socket = m_server->nextPendingConnection();
            connect(socket, &QTcpSocket::readyRead, this, [this, socket]()
            {
                const QByteArray request = socket->readAll();
                if (request.isEmpty())
                    return;

                const QString reqStr = QString::fromUtf8(request);
                const QString firstLine = reqStr.section(u'\n', 0, 0).trimmed();
                const QStringList tokens = firstLine.split(u' ');
                if (tokens.size() < 2)
                    return;

                const QString method = tokens[0];
                const QString path = tokens[1];

                QByteArray response;
                if (path == u"/.well-known/openid-configuration"_s)
                {
                    const quint16 p = m_server->serverPort();
                    QJsonObject discovery;
                    discovery[u"authorization_endpoint"_s] = u"http://127.0.0.1:%1/auth"_s.arg(p);
                    discovery[u"token_endpoint"_s] = u"http://127.0.0.1:%1/token"_s.arg(p);
                    discovery[u"userinfo_endpoint"_s] = u"http://127.0.0.1:%1/userinfo"_s.arg(p);

                    const QByteArray body = QJsonDocument(discovery).toJson(QJsonDocument::Compact);
                    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                }
                else if (path == u"/token"_s && method == u"POST"_s)
                {
                    if (!m_tokenError.isEmpty())
                    {
                        QJsonObject errObj;
                        errObj[u"error"_s] = m_tokenError;
                        errObj[u"error_description"_s] = u"Mock token error"_s;
                        const QByteArray body = QJsonDocument(errObj).toJson(QJsonDocument::Compact);
                        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                            + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                    }
                    else
                    {
                        // Generate mock ID token
                        QJsonObject header;
                        header[u"alg"_s] = u"none"_s;
                        header[u"typ"_s] = u"JWT"_s;

                        QJsonObject payload;
                        payload[u"sub"_s] = u"mock-sub-123"_s;
                        payload[u"preferred_username"_s] = u"admin_user"_s;
                        payload[u"email"_s] = u"admin@example.com"_s;

                        QJsonArray grpArr;
                        for (const QString &g : m_userGroups)
                            grpArr.append(g);
                        payload[u"groups"_s] = grpArr;

                        const QByteArray hB64 = QJsonDocument(header).toJson(QJsonDocument::Compact)
                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
                        const QByteArray pB64 = QJsonDocument(payload).toJson(QJsonDocument::Compact)
                            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
                        const QString idToken = QString::fromUtf8(hB64 + "." + pB64 + ".mock-sig");

                        QJsonObject tokenRes;
                        tokenRes[u"access_token"_s] = u"mock-access-token-xyz"_s;
                        tokenRes[u"token_type"_s] = u"Bearer"_s;
                        tokenRes[u"id_token"_s] = idToken;

                        const QByteArray body = QJsonDocument(tokenRes).toJson(QJsonDocument::Compact);
                        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                            + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                    }
                }
                else if (path == u"/userinfo"_s && method == u"GET"_s)
                {
                    QJsonObject userInfo;
                    userInfo[u"sub"_s] = u"mock-sub-123"_s;
                    userInfo[u"name"_s] = u"Admin User"_s;
                    userInfo[u"email"_s] = u"admin@example.com"_s;

                    QJsonArray grpArr;
                    for (const QString &g : m_userGroups)
                        grpArr.append(g);
                    userInfo[u"groups"_s] = grpArr;

                    const QByteArray body = QJsonDocument(userInfo).toJson(QJsonDocument::Compact);
                    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                }
                else
                {
                    response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                }

                socket->write(response);
                socket->flush();
                socket->disconnectFromHost();
            });
        }
    }

private:
    QTcpServer *m_server = nullptr;
    QString m_tokenError;
    QStringList m_userGroups {u"admins"_s, u"users"_s};
};

class MockOidcServer
{
public:
    MockOidcServer()
    {
        m_worker = new MockServerWorker();
        m_worker->moveToThread(&m_thread);
        m_thread.start();

        QMetaObject::invokeMethod(m_worker, [this]()
        {
            m_port = m_worker->start();
        }, Qt::BlockingQueuedConnection);
    }

    ~MockOidcServer()
    {
        QMetaObject::invokeMethod(m_worker, [this]()
        {
            m_worker->stop();
        }, Qt::BlockingQueuedConnection);

        m_thread.quit();
        m_thread.wait();
        delete m_worker;
    }

    quint16 serverPort() const
    {
        return m_port;
    }

    void setTokenError(const QString &error)
    {
        QMetaObject::invokeMethod(m_worker, [this, error]()
        {
            m_worker->setTokenError(error);
        }, Qt::BlockingQueuedConnection);
    }

    void setUserGroups(const QStringList &groups)
    {
        QMetaObject::invokeMethod(m_worker, [this, groups]()
        {
            m_worker->setUserGroups(groups);
        }, Qt::BlockingQueuedConnection);
    }

private:
    QThread m_thread;
    MockServerWorker *m_worker = nullptr;
    quint16 m_port = 0;
};

class TestOidcAuthenticator final : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(TestOidcAuthenticator)

public:
    TestOidcAuthenticator() = default;

private slots:
    void testConfigAndDefaults() const
    {
        Oidc::Config cfg;
        QCOMPARE(cfg.scopes, u"openid profile email groups"_s);
        QCOMPARE(cfg.displayName, u"Login with OIDC"_s);

        OidcAuthenticator auth(cfg);
        QCOMPARE(auth.isEnabled(), false);

        cfg.issuerUrl = u"https://auth.example.com/"_s;
        cfg.clientId = u"qbit-client"_s;
        cfg.adminGroup = u"admins"_s;

        OidcAuthenticator auth2(cfg);
        QCOMPARE(auth2.isEnabled(), true);
        QCOMPARE(auth2.config().issuerUrl, u"https://auth.example.com"_s); // trailing slash trimmed
        QCOMPARE(auth2.displayName(), u"Login with OIDC"_s);
    }

    void testPkceGeneration() const
    {
        const Oidc::PkcePair pkce = OidcAuthenticator::generatePkcePair();
        QVERIFY(!pkce.codeVerifier.isEmpty());
        QVERIFY(!pkce.codeChallenge.isEmpty());
        QVERIFY(pkce.codeVerifier.size() >= 43);

        // Challenge should be Base64URL(SHA256(verifier))
        const QByteArray expectedHash = QCryptographicHash::hash(pkce.codeVerifier.toUtf8(), QCryptographicHash::Sha256);
        const QString expectedChallenge = QString::fromLatin1(
            expectedHash.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
        QCOMPARE(pkce.codeChallenge, expectedChallenge);
    }

    void testStateGenerationAndManagement() const
    {
        const QString state1 = OidcAuthenticator::generateState();
        const QString state2 = OidcAuthenticator::generateState();
        QVERIFY(!state1.isEmpty());
        QVERIFY(!state2.isEmpty());
        QVERIFY(state1 != state2);

        OidcAuthenticator auth;
        QCOMPARE(auth.pendingStatesCount(), 0);

        auth.storePendingState(state1, u"verifier-123"_s, std::chrono::seconds(60));
        QCOMPARE(auth.pendingStatesCount(), 1);

        QString retrievedVerifier;
        // First consume succeeds
        QVERIFY(auth.consumeState(state1, retrievedVerifier));
        QCOMPARE(retrievedVerifier, u"verifier-123"_s);
        QCOMPARE(auth.pendingStatesCount(), 0);

        // Second consume must fail (replay protection)
        QVERIFY(!auth.consumeState(state1, retrievedVerifier));

        // Unknown state must fail
        QVERIFY(!auth.consumeState(u"non-existent-state"_s, retrievedVerifier));

        // Expired state must fail
        auth.storePendingState(state2, u"verifier-expired"_s, std::chrono::seconds(-10));
        QVERIFY(!auth.consumeState(state2, retrievedVerifier));
    }

    void testJwtPayloadDecoding() const
    {
        QJsonObject payload;
        payload[u"sub"_s] = u"user123"_s;
        payload[u"preferred_username"_s] = u"johndoe"_s;
        payload[u"email"_s] = u"john@example.com"_s;

        const QByteArray payloadB64 = QJsonDocument(payload).toJson(QJsonDocument::Compact)
            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

        const QString jwt = u"eyJhbGciOiJub25lIn0.%1.sig"_s.arg(QString::fromUtf8(payloadB64));
        const QJsonObject decoded = OidcAuthenticator::decodeJwtPayload(jwt);

        QCOMPARE(decoded.value(u"sub"_s).toString(), u"user123"_s);
        QCOMPARE(decoded.value(u"preferred_username"_s).toString(), u"johndoe"_s);
        QCOMPARE(decoded.value(u"email"_s).toString(), u"john@example.com"_s);

        // Invalid JWT
        QVERIFY(OidcAuthenticator::decodeJwtPayload(u"invalid"_s).isEmpty());
        QVERIFY(OidcAuthenticator::decodeJwtPayload(u""_s).isEmpty());
    }

    void testAdminGroupVerification() const
    {
        // No required group: always true
        QVERIFY(OidcAuthenticator::verifyAdminGroup({}, u""_s));
        QVERIFY(OidcAuthenticator::verifyAdminGroup({}, u"   "_s));

        // Array claim
        QJsonObject claimsArray;
        claimsArray[u"groups"_s] = QJsonArray {u"users"_s, u"admins"_s};
        QVERIFY(OidcAuthenticator::verifyAdminGroup(claimsArray, u"admins"_s));
        QVERIFY(!OidcAuthenticator::verifyAdminGroup(claimsArray, u"superusers"_s));

        // String claim (single or space/comma-separated)
        QJsonObject claimsString;
        claimsString[u"groups"_s] = u"users admins developers"_s;
        QVERIFY(OidcAuthenticator::verifyAdminGroup(claimsString, u"admins"_s));
        QVERIFY(OidcAuthenticator::verifyAdminGroup(claimsString, u"developers"_s));
        QVERIFY(!OidcAuthenticator::verifyAdminGroup(claimsString, u"root"_s));

        // Keycloak realm_access.roles
        QJsonObject realmAccess;
        realmAccess[u"roles"_s] = QJsonArray {u"default-roles"_s, u"admin"_s};
        QJsonObject claimsKeycloak;
        claimsKeycloak[u"realm_access"_s] = realmAccess;
        QVERIFY(OidcAuthenticator::verifyAdminGroup(claimsKeycloak, u"admin"_s));
        QVERIFY(!OidcAuthenticator::verifyAdminGroup(claimsKeycloak, u"moderator"_s));
    }

    void testExtractUserIdentifier() const
    {
        QJsonObject c1;
        c1[u"preferred_username"_s] = u"preferred_user"_s;
        c1[u"username"_s] = u"regular_user"_s;
        c1[u"email"_s] = u"email@example.com"_s;
        QCOMPARE(OidcAuthenticator::extractUserIdentifier(c1), u"preferred_user"_s);

        QJsonObject c2;
        c2[u"username"_s] = u"regular_user"_s;
        c2[u"email"_s] = u"email@example.com"_s;
        QCOMPARE(OidcAuthenticator::extractUserIdentifier(c2), u"regular_user"_s);

        QJsonObject c3;
        c3[u"email"_s] = u"email@example.com"_s;
        QCOMPARE(OidcAuthenticator::extractUserIdentifier(c3), u"email@example.com"_s);

        QJsonObject c4;
        c4[u"sub"_s] = u"sub-999"_s;
        QCOMPARE(OidcAuthenticator::extractUserIdentifier(c4), u"sub-999"_s);

        QJsonObject cEmpty;
        QCOMPARE(OidcAuthenticator::extractUserIdentifier(cEmpty), u""_s);
    }

    void testBuildAuthorizationUrl() const
    {
        Oidc::Config cfg;
        cfg.issuerUrl = u"https://auth.example.com"_s;
        cfg.clientId = u"my-app"_s;
        cfg.scopes = u"openid email"_s;

        OidcAuthenticator auth(cfg);
        auth.setEndpoints(u"https://auth.example.com/oauth2/auth"_s, u"https://auth.example.com/oauth2/token"_s, u"https://auth.example.com/userinfo"_s);

        const QString authUrl = auth.buildAuthorizationUrl(u"https://qbit.example.com/api/v2/auth/oidcCallback"_s);
        QVERIFY(!authUrl.isEmpty());
        QVERIFY(authUrl.startsWith(u"https://auth.example.com/oauth2/auth?"_s));

        const QUrl parsedUrl(authUrl);
        const QUrlQuery query(parsedUrl);
        QCOMPARE(query.queryItemValue(u"response_type"_s), u"code"_s);
        QCOMPARE(query.queryItemValue(u"client_id"_s), u"my-app"_s);
        QCOMPARE(query.queryItemValue(u"redirect_uri"_s), u"https://qbit.example.com/api/v2/auth/oidcCallback"_s);
        QCOMPARE(query.queryItemValue(u"scope"_s), u"openid email"_s);
        QCOMPARE(query.queryItemValue(u"code_challenge_method"_s), u"S256"_s);
        QVERIFY(!query.queryItemValue(u"state"_s).isEmpty());
        QVERIFY(!query.queryItemValue(u"code_challenge"_s).isEmpty());

        // Verify that state was registered
        QCOMPARE(auth.pendingStatesCount(), 1);
    }

    void testMockServerIntegration() const
    {
        MockOidcServer server;
        const quint16 port = server.serverPort();
        QVERIFY(port > 0);

        Oidc::Config cfg;
        cfg.issuerUrl = u"http://127.0.0.1:%1"_s.arg(port);
        cfg.clientId = u"mock-client"_s;
        cfg.clientSecret = u"mock-secret"_s;
        cfg.adminGroup = u"admins"_s;

        OidcAuthenticator auth(cfg);
        QVERIFY(auth.loadDiscovery(5000));
        QVERIFY(auth.isDiscoveryLoaded());
        QCOMPARE(auth.authorizationEndpoint(), u"http://127.0.0.1:%1/auth"_s.arg(port));
        QCOMPARE(auth.tokenEndpoint(), u"http://127.0.0.1:%1/token"_s.arg(port));
        QCOMPARE(auth.userinfoEndpoint(), u"http://127.0.0.1:%1/userinfo"_s.arg(port));

        // Build authorization URL
        const QString authUrl = auth.buildAuthorizationUrl(u"http://127.0.0.1:8080/callback"_s);
        QVERIFY(!authUrl.isEmpty());
        const QUrl parsedAuthUrl(authUrl);
        const QUrlQuery q(parsedAuthUrl);
        const QString state = q.queryItemValue(u"state"_s);
        QVERIFY(!state.isEmpty());

        // Exchange code with mock server
        const auto tokenRes = auth.exchangeCodeAndVerify(u"mock-code"_s, state, u"http://127.0.0.1:8080/callback"_s, 5000);
        QVERIFY(tokenRes.success);
        QCOMPARE(tokenRes.username, u"admin_user"_s);
        QVERIFY(!tokenRes.accessToken.isEmpty());
        QVERIFY(!tokenRes.idToken.isEmpty());

        // Test group failure scenario
        server.setUserGroups({u"guests"_s}); // no "admins"
        const QString authUrl2 = auth.buildAuthorizationUrl(u"http://127.0.0.1:8080/callback"_s);
        const QUrl parsedAuthUrl2(authUrl2);
        const QString state2 = QUrlQuery(parsedAuthUrl2).queryItemValue(u"state"_s);
        const auto groupFailRes = auth.exchangeCodeAndVerify(u"mock-code"_s, state2, u"http://127.0.0.1:8080/callback"_s, 5000);
        QVERIFY(!groupFailRes.success);
        QVERIFY(groupFailRes.error.contains(u"not a member of the required admin group"_s));

        // Test token endpoint error scenario
        server.setTokenError(u"invalid_grant"_s);
        const QString authUrl3 = auth.buildAuthorizationUrl(u"http://127.0.0.1:8080/callback"_s);
        const QUrl parsedAuthUrl3(authUrl3);
        const QString state3 = QUrlQuery(parsedAuthUrl3).queryItemValue(u"state"_s);
        const auto tokenErrorRes = auth.exchangeCodeAndVerify(u"mock-code"_s, state3, u"http://127.0.0.1:8080/callback"_s, 5000);
        QVERIFY(!tokenErrorRes.success);
        QVERIFY(tokenErrorRes.error.contains(u"Token exchange failed"_s) || tokenErrorRes.error.contains(u"invalid_grant"_s));
    }
};

QTEST_MAIN(TestOidcAuthenticator)
#include "testoidcauthenticator.moc"
