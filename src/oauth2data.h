/*
 * This file is part of oauth2 plugin
 *
 * Copyright (C) 2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OAUTH2DATA_H
#define OAUTH2DATA_H

#include <sessiondata.h>

class OAuth2PluginTest;
namespace OAuth2PluginNS {
    /*!
 * @class OAuth2PluginData
 * Data container to hold values for OAuth 2.0 authentication session.
 */
    class OAuth2PluginData : public SignOn::SessionData
    {
    friend class ::OAuth2PluginTest;
    public:
        using SignOn::SessionData::SessionData;

        /*!
         * hostname of the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, Host);

        /*!
         * hostname component of the authorization endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AuthHost);

        /*!
         * hostname component of the token endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, TokenHost);

        /*!
         * authorization endpoint of the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AuthPath);

        /*!
         * token endpoint of the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, TokenPath);

        /*!
         * port component of the token endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(quint16, AuthPort);

        /*!
         * port component of the authorization endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(quint16, TokenPort);

        /*!
         * Application client ID and secret
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, ClientId);
        SIGNON_SESSION_DECLARE_PROPERTY(QString, ClientSecret);

        /*!
         * Set this to true if the server does not conform to the OAuth 2.0
         * specification in that it does not support supplying client ID and
         * secret via basic HTTP authorization.
         */
        SIGNON_SESSION_DECLARE_PROPERTY(bool, ForceClientAuthViaRequestBody);

        /*!
         * Set this to true if the access token returned by the previous
         * authentication is invalid. This instructs the OAuth plugin to
         * generate a new access token.
         */
        SIGNON_SESSION_DECLARE_PROPERTY(bool, ForceTokenRefresh);

        /*!
         * Set this to true if the provider does not support passing the
         * "state" parameter around, as described in
         * http://tools.ietf.org/html/rfc6749#appendix-A.5
         */
        SIGNON_SESSION_DECLARE_PROPERTY(bool, DisableStateParameter);

        /*!
         * redirection URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, RedirectUri);

        /*!
         * access scope
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QStringList, Scope);

        /*!
         * response type
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QStringList, ResponseType);

        /*!
         * query component of the authorization endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AuthQuery);

        /*!
         * query component of the token endpoint URI
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, TokenQuery);
    };

    class OAuth2PluginTokenData : public SignOn::SessionData
    {
    public:
        /*!
         * Access token received from the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, AccessToken);
        /*!
         * OpenID token received from the server (optional)
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, IdToken);
        /*!
         * Refresh token received from the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QString, RefreshToken);
        /*!
         * Access token expiry time
         */
        SIGNON_SESSION_DECLARE_PROPERTY(int, ExpiresIn);
        /*!
         * Granted permissions
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QStringList, Scope);
        /*!
         * Any extra (non standard) fields which were returned by the server
         */
        SIGNON_SESSION_DECLARE_PROPERTY(QVariantMap, ExtraFields);
    };

} // namespace OAuth2PluginNS


#endif // OAUTH2DATA_H
