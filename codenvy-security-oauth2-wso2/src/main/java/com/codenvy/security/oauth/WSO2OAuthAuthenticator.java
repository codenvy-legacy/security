/*******************************************************************************
 * Copyright (c) 2012-2014 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package com.codenvy.security.oauth;

import com.codenvy.api.auth.shared.dto.OAuthToken;
import com.codenvy.commons.json.JsonHelper;
import com.codenvy.commons.json.JsonParseException;
import com.codenvy.commons.lang.IoUtil;
import com.codenvy.security.oauth.shared.User;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.CredentialStore;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;

import org.everrest.core.impl.provider.json.JsonValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** OAuth authentication for wso2 account. */
@Singleton
public class WSO2OAuthAuthenticator extends OAuthAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(WSO2OAuthAuthenticator.class);

    private static final String SCOPE = "openid";

    final String userUri;

    @Inject
    public WSO2OAuthAuthenticator(@Named("oauth.wso2.clientid") String clientId,
                                  @Named("oauth.wso2.clientsecret") String clientSecret,
                                  @Named("oauth.wso2.redirecturis") String[] redirectUris,
                                  @Named("oauth.wso2.authuri") String authUri,
                                  @Named("oauth.wso2.tokenuri") String tokenUri,
                                  @Named("oauth.wso2.useruri") String userUri,
                                  CredentialStore credentialStore) {
        super(new AuthorizationCodeFlow.Builder(
                      BearerToken.authorizationHeaderAccessMethod(),
                      new NetHttpTransport(),
                      new JacksonFactory(),
                      new GenericUrl(tokenUri),
                      new ClientParametersAuthentication(
                              clientId,
                              clientSecret),
                      clientId,
                      authUri
              )
                      .setScopes(Arrays.asList(SCOPE))
                      .setCredentialStore(credentialStore)
                      .setCredentialStore(credentialStore).build(),
              Arrays.asList(redirectUris));
        this.userUri = userUri;
    }

    /** {@inheritDoc} */
    @Override
    public User getUser(OAuthToken accessToken) throws OAuthAuthenticationException {
        URL getUserUrL;
        Map<String, String> params = new HashMap<>();
        params.put("Authorization", "Bearer " + accessToken.getToken());
        try {
            getUserUrL = new URL(String.format("%s?schema=%s", userUri, SCOPE));
            JsonValue userValue = doRequest(getUserUrL, params);
            User user = new Wso2User();
            user.setEmail(userValue.getElement("http://wso2.org/claims/emailaddress").getStringValue());
            user.setName(userValue.getElement("http://wso2.org/claims/fullname").getStringValue());
            return user;
        } catch (JsonParseException | IOException e) {
            throw new OAuthAuthenticationException(e.getMessage(), e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public String getOAuthProvider() {
        return "wso2";
    }

    @Override
    public OAuthToken getToken(String userId) throws IOException {
        final OAuthToken token = super.getToken(userId);
        if (token != null) {
            token.setScope(SCOPE);
        }
        return token;
    }

    private JsonValue doRequest(URL tokenInfoUrl, Map<String, String> params) throws IOException, JsonParseException {
        HttpURLConnection http = null;
        try {
            http = (HttpURLConnection)tokenInfoUrl.openConnection();
            http.setRequestMethod("GET");
            if (params != null) {
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    http.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            int responseCode = http.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                LOG.warn("Can not receive wso2 token by path: {}. Response status: {}. Error message: {}",
                         tokenInfoUrl.toString(), responseCode, IoUtil.readStream(http.getErrorStream()));
                return null;
            }

            JsonValue result;
            try (InputStream input = http.getInputStream()) {
                result = JsonHelper.parseJson(input);
            }
            return result;
        } finally {
            if (http != null) {
                http.disconnect();
            }
        }
    }
}
