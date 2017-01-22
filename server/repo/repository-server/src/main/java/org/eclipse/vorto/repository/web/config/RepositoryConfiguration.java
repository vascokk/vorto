/**
 * Copyright (c) 2015-2016 Bosch Software Innovations GmbH and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 * Bosch Software Innovations GmbH - Please refer to git log
 */
package org.eclipse.vorto.repository.web.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
public class RepositoryConfiguration {

	@Value("${repo.configFile}")
	private String repositoryConfigFile = null;
	@Bean
	public org.modeshape.jcr.RepositoryConfiguration repoConfiguration() throws Exception {
		return org.modeshape.jcr.RepositoryConfiguration.read(new ClassPathResource(repositoryConfigFile).getURL());
	}
	
	@Bean
	public TokenStore tokenStore() {
	    return new InMemoryTokenStore();
	}

	@Bean
	public AuthorizationServerTokenServices tokenServices() {
	    final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
	    defaultTokenServices.setAccessTokenValiditySeconds(-1);

	    defaultTokenServices.setTokenStore(tokenStore());
	    return defaultTokenServices;
	}
}
