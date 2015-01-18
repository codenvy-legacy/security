/*******************************************************************************
 * Copyright (c) 2012-2015 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package com.codenvy.security.oauth;

import com.codenvy.api.auth.oauth.OAuthTokenProvider;
import com.codenvy.api.auth.shared.dto.OAuthToken;
import com.codenvy.commons.env.EnvironmentContext;
import com.codenvy.commons.json.JsonHelper;
import com.codenvy.commons.lang.IoUtil;
import com.google.inject.name.Named;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;

import static com.codenvy.commons.lang.IoUtil.readAndCloseQuietly;

/**
 * Allow get token from OAuth service over http.
 */
public class RemoteOAuthTokenProvider implements OAuthTokenProvider {
    private static final Logger LOG = LoggerFactory.getLogger(RemoteOAuthTokenProvider.class);

    @Inject
    @Named("api.endpoint")
    protected String apiEndpoint;

    @Override
    public OAuthToken getToken(String oauthProviderName, String userId) throws IOException {
        if (!userId.isEmpty()) {

            String authToken = null;
            authToken = EnvironmentContext.getCurrent().getUser().getToken();
            if (authToken != null) {

                try {
                    UriBuilder ub = UriBuilder.fromUri(apiEndpoint)
                                              .path("/oauth/token/")
                                              .queryParam("oauth_provider", oauthProviderName)
                                              .queryParam("token", authToken);


                    HttpURLConnection conn = null;
                    try {
                        conn = (HttpURLConnection)ub.build().toURL().openConnection();
                        conn.setRequestMethod("GET");
                        int code = conn.getResponseCode();
                        if (code / 100 != 2) {

                            InputStream errorStream = conn.getErrorStream();
                            LOG.error("Response code {}, response message{}", code, IoUtil.readStream(errorStream));
                            return null;
                        } else if (code == 204) {
                            LOG.warn("Token not found  for {}", userId);
                            return null;
                        }

                        return JsonHelper.fromJson(new StringReader(readAndCloseQuietly(conn.getInputStream())), OAuthToken.class, null);
                    } finally {
                        if (conn != null) {
                            conn.disconnect();
                        }
                    }
                } catch (Exception e) {
                    // ignore all error when generate signature
                    LOG.error(e.getMessage(), e);
                }
            }
        }
        return null;
    }


}
