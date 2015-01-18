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

import com.codenvy.inject.DynaModule;
import com.google.inject.AbstractModule;
import com.google.inject.multibindings.Multibinder;

   /**
     * Setup ProjectLockerOAuthAuthenticator in guice container.
     *
     * @author Max Shaposhnik
     */
@DynaModule
public class ProjectLockerModule extends AbstractModule {
       @Override
       protected void configure() {
           Multibinder<OAuthAuthenticator> oAuthAuthenticators = Multibinder.newSetBinder(binder(), OAuthAuthenticator.class);
           oAuthAuthenticators.addBinding().to(ProjectLockerOAuthAuthenticator.class);
       }
}
