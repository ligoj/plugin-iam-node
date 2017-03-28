package org.ligoj.app.plugin.iam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.transaction.Transactional;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamConfigurationProvider;
import org.ligoj.app.model.Node;
import org.ligoj.app.model.Parameter;
import org.ligoj.app.model.ParameterValue;
import org.ligoj.app.plugin.id.resource.IdentityServicePlugin;
import org.ligoj.app.resource.AbstractServerTest;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test class of {@link NodeBasedIamProvider}
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
public class NodeBasedIamProviderTest extends AbstractServerTest {

	@Autowired
	private ConfigurationResource configuration;

	@Before
	public void prepareSubscription() throws IOException {
		persistEntities("csv",
				new Class[] { SystemConfiguration.class, Node.class, Parameter.class, ParameterValue.class },
				StandardCharsets.UTF_8.name());
	}

	@Test
	public void authenticateNoSecondary() throws Exception {
		final Authentication authentication = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication authentication2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final NodeBasedIamProvider provider = new NodeBasedIamProvider();
		final IdentityServicePlugin servicePlugin = Mockito.mock(IdentityServicePlugin.class);
		provider.configuration = configuration;
		provider.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(
				provider.servicePluginLocator.getResourceExpected("service:id:ldap:dig", IdentityServicePlugin.class))
				.thenReturn(servicePlugin);
		Mockito.when(servicePlugin.authenticate(authentication, "service:id:ldap:dig", true))
				.thenReturn(authentication2);
		Assert.assertSame(authentication2, provider.authenticate(authentication));
	}

	@Test
	public void authenticateSecondaryAccept() throws Exception {
		final Authentication authentication = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication authentication2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final IdentityServicePlugin servicePlugin = Mockito.mock(IdentityServicePlugin.class);
		final NodeBasedIamProvider provider = new NodeBasedIamProvider();
		provider.configuration = configuration;
		provider.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(provider.servicePluginLocator.getResource("service:id:ldap:adu", IdentityServicePlugin.class))
				.thenReturn(servicePlugin);
		Mockito.when(servicePlugin.accept(authentication, "service:id:ldap:adu")).thenReturn(true);
		Mockito.when(servicePlugin.authenticate(authentication, "service:id:ldap:adu", false))
				.thenReturn(authentication2);
		Assert.assertSame(authentication2, provider.authenticate(authentication));
		Mockito.verify(provider.servicePluginLocator, VerificationModeFactory.times(0))
				.getResource("service:id:ldap:dig", IdentityServicePlugin.class);
	}

	@Test
	public void authenticateSecondaryDontAccept() throws Exception {
		final Authentication authentication = new UsernamePasswordAuthenticationToken("user1", "secret");
		final Authentication authentication2 = new UsernamePasswordAuthenticationToken("user1v2", "secret");
		final IdentityServicePlugin servicePluginSecondary = Mockito.mock(IdentityServicePlugin.class);
		final IdentityServicePlugin servicePluginPrimary = Mockito.mock(IdentityServicePlugin.class);
		final NodeBasedIamProvider provider = new NodeBasedIamProvider();
		provider.configuration = configuration;
		provider.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		Mockito.when(provider.servicePluginLocator.getResource("service:id:ldap:adu", IdentityServicePlugin.class))
				.thenReturn(servicePluginSecondary);
		Mockito.when(servicePluginPrimary.authenticate(authentication, "service:id:ldap:dig", true))
				.thenReturn(authentication2);
		Mockito.when(
				provider.servicePluginLocator.getResourceExpected("service:id:ldap:dig", IdentityServicePlugin.class))
				.thenReturn(servicePluginPrimary);
		Assert.assertSame(authentication2, provider.authenticate(authentication));
		Mockito.verify(servicePluginSecondary, VerificationModeFactory.times(0)).authenticate(authentication,
				"service:id:ldap:adu", false);
	}

	@Test
	public void getConfiguration() {
		final NodeBasedIamProvider provider = new NodeBasedIamProvider();
		provider.configuration = configuration;
		provider.servicePluginLocator = Mockito.mock(ServicePluginLocator.class);
		final IamConfiguration iamConfiguration = Mockito.mock(IamConfiguration.class);
		final IamConfigurationProvider servicePlugin = Mockito.mock(IamConfigurationProvider.class);
		Mockito.when(servicePlugin.getConfiguration("service:id:ldap:dig")).thenReturn(iamConfiguration);
		Mockito.when(provider.servicePluginLocator.getResourceExpected("service:id:ldap:dig",
				IamConfigurationProvider.class)).thenReturn(servicePlugin);

		Assert.assertSame(iamConfiguration, provider.getConfiguration());
	}
}
