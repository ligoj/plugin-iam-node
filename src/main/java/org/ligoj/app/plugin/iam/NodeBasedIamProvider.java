package org.ligoj.app.plugin.iam;

import javax.cache.annotation.CacheResult;

import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.api.FeaturePlugin;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamConfigurationProvider;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.plugin.id.resource.IdentityServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Identity and Access Management provider based on node. A primary node is used
 * to fetch user details. The secondary provider can authenticate some users
 * before the primary, when their login is accepted.
 */
@Component
@Slf4j
public class NodeBasedIamProvider implements IamProvider, FeaturePlugin {

	@Autowired
	protected ServicePluginLocator servicePluginLocator;

	@Autowired
	protected ConfigurationResource configuration;

	/**
	 * Secondary user nodes.
	 * 
	 * @return Secondary user nodes. May be empty.
	 */
	protected String[] getSecondary() {
		return StringUtils.defaultString(configuration.get("iam.secondary"), "").split(",");
	}

	/**
	 * Secondary user nodes.
	 * 
	 * @return Secondary user nodes. Should not be <code>null</code>.
	 */
	protected String getPrimary() {
		return configuration.get("iam.primary");
	}

	@Override
	public Authentication authenticate(final Authentication authentication) {

		// Determine the right provider to authenticate among the IAM nodes
		for (final String nodeId : getSecondary()) {
			final IdentityServicePlugin resource = servicePluginLocator.getResource(nodeId,
					IdentityServicePlugin.class);
			if (resource == null) {
				// Ignore IAM provider not found
				log.info("IAM node {} does not exist", nodeId);
			} else if (resource.accept(authentication, nodeId)) {
				// IAM provider has been found, use it for this authentication
				return resource.authenticate(authentication, nodeId, false);
			}
		}

		// Primary authentication
		final String primary = getPrimary();
		return servicePluginLocator.getResourceExpected(primary, IdentityServicePlugin.class)
				.authenticate(authentication, primary, true);
	}

	@Override
	@CacheResult(cacheName = "iam-node-configuration")
	public IamConfiguration getConfiguration() {
		final String primary = getPrimary();
		return servicePluginLocator.getResourceExpected(primary, IamConfigurationProvider.class)
				.getConfiguration(primary);
	}

	@Override
	public String getKey() {
		return "feature:iam:node";
	}

}
