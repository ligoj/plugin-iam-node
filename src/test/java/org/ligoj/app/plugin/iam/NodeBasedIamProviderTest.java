/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.iam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.transaction.Transactional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamConfigurationProvider;
import org.ligoj.app.model.Node;
import org.ligoj.app.model.Parameter;
import org.ligoj.app.model.ParameterValue;
import org.ligoj.app.plugin.id.resource.IdentityServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.AbstractJpaTest;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Test class of {@link NodeBasedIamProvider}
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
class NodeBasedIamProviderTest extends AbstractJpaTest {

	@Autowired
	private ConfigurationResource configuration;

	@Autowired
	private NodeBasedIamProvider provider;

	@Autowired
	protected CacheManager cacheManager;

	@BeforeEach
	void prepareSubscription() throws IOException {
		persistEntities("csv",
				new Class[] { SystemConfiguration.class, Node.class, Parameter.class, ParameterValue.class },
				StandardCharsets.UTF_8.name());
		cacheManager.getCache("configuration").clear();
	}

	@Test
	void authenticateNoSecondary() {
		authenticateNoSecondaryInternal();
	}

	@Test
	void authenticateSecondaryEmptyOrNull() {
		configuration.put("feature:iam:node:secondary", " ,,  ");
		authenticateNoSecondaryInternal();
	}

	private void authenticateNoSecondaryInternal() {
		final Authentication auth = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication auth2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final NodeBasedIamProvider provider = newResource();
		final IdentityServicePlugin servicePlugin = Mockito.mock(IdentityServicePlugin.class);
		provider.locator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(provider.locator.getResource("service:id:ldap:dig", IdentityServicePlugin.class))
				.thenReturn(servicePlugin);
		Mockito.when(servicePlugin.authenticate(auth, "service:id:ldap:dig", true)).thenReturn(auth2);
		Assertions.assertSame(auth2, provider.authenticate(auth));
	}

	@Test
	void authenticateNoPrimary() {
		configuration.delete("feature:iam:node:secondary");
		configuration.delete("feature:iam:node:primary");

		final Authentication auth = new UsernamePasswordAuthenticationToken("user1", "secret");
		final NodeBasedIamProvider provider = newResource();
		provider.locator = Mockito.mock(ServicePluginLocator.class);

		// Empty provider returns the same authentication
		Assertions.assertSame(auth, provider.authenticate(auth));
	}

	private NodeBasedIamProvider newResource() {
		final NodeBasedIamProvider provider = new NodeBasedIamProvider();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(provider);
		provider.configuration = configuration;
		provider.self = provider;
		return provider;
	}

	@Test
	void authenticateSecondaryAccept() {
		final Authentication auth = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication auth2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final IdentityServicePlugin servicePlugin = Mockito.mock(IdentityServicePlugin.class);
		final NodeBasedIamProvider provider = newResource();
		provider.locator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(provider.locator.getResource("service:id:ldap:adu", IdentityServicePlugin.class))
				.thenReturn(servicePlugin);
		Mockito.when(servicePlugin.accept(auth, "service:id:ldap:adu")).thenReturn(true);
		Mockito.when(servicePlugin.authenticate(auth, "service:id:ldap:adu", false)).thenReturn(auth2);
		Assertions.assertSame(auth2, provider.authenticate(auth));
		Mockito.verify(provider.locator, VerificationModeFactory.times(0)).getResource("service:id:ldap:dig",
				IdentityServicePlugin.class);
	}

	@Test
	void authenticateSecondaryDontAccept() {
		final Authentication auth = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication auth2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final IdentityServicePlugin secondary = Mockito.mock(IdentityServicePlugin.class);
		final IdentityServicePlugin primary = Mockito.mock(IdentityServicePlugin.class);
		final NodeBasedIamProvider provider = newResource();
		provider.locator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(provider.locator.getResource("service:id:ldap:adu", IdentityServicePlugin.class))
				.thenReturn(secondary);
		Mockito.when(primary.authenticate(auth, "service:id:ldap:dig", true)).thenReturn(auth2);
		Mockito.when(provider.locator.getResource("service:id:ldap:dig", IdentityServicePlugin.class))
				.thenReturn(primary);
		Assertions.assertSame(auth2, provider.authenticate(auth));
		Mockito.verify(secondary, VerificationModeFactory.times(0)).authenticate(auth, "service:id:ldap:adu", false);
	}

	@Test
	void getConfiguration() {
		final NodeBasedIamProvider provider = newResource();
		provider.locator = Mockito.mock(ServicePluginLocator.class);
		final IamConfiguration iamConfiguration = Mockito.mock(IamConfiguration.class);
		final IamConfigurationProvider servicePlugin = Mockito.mock(IamConfigurationProvider.class);
		Mockito.when(servicePlugin.getConfiguration("service:id:ldap:dig")).thenReturn(iamConfiguration);
		Mockito.when(provider.locator.getResource("service:id:ldap:dig", IamConfigurationProvider.class))
				.thenReturn(servicePlugin);

		Assertions.assertSame(iamConfiguration, provider.getConfiguration());
	}

	@Test
	void getConfigurationNotExist() {
		applicationContext.getAutowireCapableBeanFactory().autowireBean(provider);
		provider.configuration = configuration;
		provider.locator = Mockito.mock(ServicePluginLocator.class);
		Assertions.assertNotNull(provider.getConfiguration());
	}

	@Test
	void getKey() {
		Assertions.assertEquals("feature:iam:node", new NodeBasedIamProvider().getKey());
	}

	@Test
	void install() {
		csvForJpa.cleanup(SystemConfiguration.class);
		final NodeBasedIamProvider provider = newResource();
		provider.install();
		Assertions.assertEquals("service:id:ldap:dig", configuration.get("feature:iam:node:primary"));
	}

	@Test
	void installNoIdFallBackToEmpty() {
		csvForJpa.cleanup(SystemConfiguration.class, Node.class, Parameter.class, ParameterValue.class);
		final NodeBasedIamProvider provider = newResource();
		provider.install();
		Assertions.assertEquals("empty", configuration.get("feature:iam:node:primary"));
	}
}
