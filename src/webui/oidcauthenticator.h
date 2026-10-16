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

#pragma once

#include <chrono>

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QUrl>

class QThread;
class OidcHttpWorker;

namespace Oidc
{
    struct Config
    {
        QString issuerUrl {};
        QString clientId {};
        QString clientSecret {};
        QString redirectUri {};
        QString scopes = QStringLiteral("openid profile email groups");
        QString adminGroup {};
        QString displayName = QStringLiteral("Login with OIDC");
    };

    struct PendingState
    {
        QString codeVerifier {};
        QDateTime expiresAt {};
    };

    struct TokenResponse
    {
        bool success = false;
        QString error {};
        QString accessToken {};
        QString idToken {};
        QJsonObject idTokenPayload {};
        QJsonObject userInfo {};
        QJsonObject combinedClaims {};
        QString username {};
    };

    struct PkcePair
    {
        QString codeVerifier {};
        QString codeChallenge {};
    };
}

class OidcAuthenticator : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(OidcAuthenticator)

public:
    explicit OidcAuthenticator(QObject *parent = nullptr);
    explicit OidcAuthenticator(const Oidc::Config &config, QObject *parent = nullptr);
    ~OidcAuthenticator() override;

    bool isEnabled() const;
    const Oidc::Config &config() const;
    QString displayName() const;

    // Helper functions (static for unit tests)
    static Oidc::PkcePair generatePkcePair();
    static QString generateState();
    static QJsonObject decodeJwtPayload(const QString &jwt);
    static bool verifyAdminGroup(const QJsonObject &claims, const QString &requiredGroup);
    static QString extractUserIdentifier(const QJsonObject &claims);

    // State management
    void storePendingState(const QString &state, const QString &codeVerifier, std::chrono::seconds ttl = std::chrono::seconds(600));
    bool consumeState(const QString &state, QString &codeVerifier);
    int pendingStatesCount() const;
    void purgeExpiredStates();

    // Endpoints & Discovery
    bool loadDiscovery(int timeoutMs = 10000);
    void setEndpoints(const QString &authEndpoint, const QString &tokenEndpoint, const QString &userinfoEndpoint);
    QString authorizationEndpoint() const;
    QString tokenEndpoint() const;
    QString userinfoEndpoint() const;
    bool isDiscoveryLoaded() const;

    // URL building
    QString buildAuthorizationUrl(const QString &effectiveRedirectUri = QString());

    // Token exchange and claim verification
    Oidc::TokenResponse exchangeCodeAndVerify(const QString &code, const QString &state, const QString &effectiveRedirectUri = QString(), int timeoutMs = 10000);

private:
    void initFromEnvironment();
    void startWorkerThread();
    void stopWorkerThread();

    QByteArray executeHttpGet(const QUrl &url, const QMap<QString, QString> &headers, int timeoutMs, int &httpCode, QString &errorMsg);
    QByteArray executeHttpPost(const QUrl &url, const QByteArray &postData, const QMap<QString, QString> &headers, int timeoutMs, int &httpCode, QString &errorMsg);

    Oidc::Config m_config;
    QString m_authorizationEndpoint;
    QString m_tokenEndpoint;
    QString m_userinfoEndpoint;
    bool m_discoveryLoaded = false;

    mutable QMutex m_mutex;
    QHash<QString, Oidc::PendingState> m_pendingStates;

    QThread *m_workerThread = nullptr;
    OidcHttpWorker *m_worker = nullptr;
};
