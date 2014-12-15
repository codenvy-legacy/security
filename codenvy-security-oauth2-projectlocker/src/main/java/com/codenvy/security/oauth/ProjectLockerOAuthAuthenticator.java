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
import com.codenvy.security.oauth.shared.User;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.CredentialStore;
import com.google.api.client.auth.oauth2.MemoryCredentialStore;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

/**
 * OAuth authentication for ProjectLocker account.
 *
 * @author Max Shaposhnik
 */
public class ProjectLockerOAuthAuthenticator extends OAuthAuthenticator {

    private static final Logger LOG = LoggerFactory.getLogger(ProjectLockerOAuthAuthenticator.class);

    @Inject
    public ProjectLockerOAuthAuthenticator(@Named("oauth.projectlocker.clientid") String clientId,
                                           @Named("oauth.projectlocker.clientsecret") String clientSecret,
                                           @Named("oauth.projectlocker.redirecturis") String[] redirectUris,
                                           @Named("oauth.projectlocker.authuri") String authUri,
                                           @Named("oauth.projectlocker.tokenuri") String tokenUri) {
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
                      .setScopes(Collections.<String>emptyList())
                      .setCredentialStore(new MemoryCredentialStore())
                      .build(),
              Arrays.asList(redirectUris)
             );
    }

    @Override
    public User getUser(OAuthToken accessToken) throws OAuthAuthenticationException {
        return null;
    }

    @Override
    public OAuthToken getToken(String userId) throws IOException {
        return super.getToken(userId);
    }

    @Override
    public final String getOAuthProvider() {
        return "projectlocker";
    }
}
