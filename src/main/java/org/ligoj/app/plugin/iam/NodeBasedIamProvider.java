/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.iam;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.cache.annotation.CacheResult;

import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.api.FeaturePlugin;
import org.ligoj.app.dao.NodeRepository;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamConfigurationProvider;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.iam.empty.EmptyIamProvider;
import org.ligoj.app.model.Node;
import org.ligoj.app.plugin.id.resource.IdentityServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Identity and Access Management provider based on node. A primary node is used to fetch user details. The secondary
 * provider can authenticate some users before the primary, when their login is accepted.
 */
@Component
@Slf4j
@Order(10)
public class NodeBasedIamProvider implements IamProvider, FeaturePlugin {

	private static final String KEY = "feature:iam:node";

	/**
	 * Configuration key for IAM primary node.
	 */
	private static final String PRIMARY_CONFIGURATION = KEY + ":primary";

	/**
	 * Configuration key for IAM secondary node.
	 */
	private static final String SECONDARY_CONFIGURATION = KEY + ":secondary";

	@Autowired
	protected ServicePluginLocator locator;

	@Autowired
	protected ConfigurationResource configuration;

	@Autowired
	private NodeRepository nodeRepository;

	@Autowired
	protected NodeBasedIamProvider self;

	/**
	 * The fail-safe IAM provider.
	 */
	@Autowired
	protected EmptyIamProvider emptyProvider;

	private IamConfiguration iamConfiguration;

	/**
	 * Secondary user nodes.
	 *
	 * @return Secondary user nodes. May be empty.
	 */
	private List<String> getSecondary() {
		return Arrays.stream(configuration.get(SECONDARY_CONFIGURATION, "").split(",")).filter(StringUtils::isNotBlank)
				.collect(Collectors.toList());
	}

	/**
	 * Primary user node.
	 *
	 * @return Primary user node. Never <code>null</code>.
	 */
	protected String getPrimary() {
		return configuration.get(PRIMARY_CONFIGURATION);
	}

	@Override
	public Authentication authenticate(final Authentication authentication) {

		// Determine the right provider to authenticate among the IAM nodes
		for (final String nodeId : getSecondary()) {
			final IdentityServicePlugin plugin = locator.getResource(nodeId, IdentityServicePlugin.class);
			if (plugin == null) {
				// Ignore IAM provider not found
				log.info("Secondary IAM node {} does not exist", nodeId);
			} else if (plugin.accept(authentication, nodeId)) {
				// IAM provider has been found, use it for this authentication
				return plugin.authenticate(authentication, nodeId, false);
			}
		}

		// Primary authentication
		final String primary = getPrimary();
		return Optional.ofNullable(locator.getResource(primary, IdentityServicePlugin.class))
				.map(p -> p.authenticate(authentication, primary, true)).orElseGet(() -> {
					log.info("Primary IAM node {} does not exist, use empty IAM", primary);
					return emptyProvider.authenticate(authentication);
				});
	}

	@Override
	public IamConfiguration getConfiguration() {
		self.ensureCachedConfiguration();
		return Optional.ofNullable(iamConfiguration).orElseGet(this::refreshConfiguration);
	}

	@CacheResult(cacheName = "iam-node-configuration")
	public boolean ensureCachedConfiguration() {
		refreshConfiguration();
		return true;
	}

	private IamConfiguration refreshConfiguration() {
		// Only primary node is used for repository configuration
		final String primary = getPrimary();
		return Optional.ofNullable(locator.getResource(primary, IamConfigurationProvider.class))
				.map(p -> p.getConfiguration(primary)).orElseGet(() -> {
					// Node or related plug-in are not available
					log.error("Primary IAM node {} does not exist, use empty IAM", primary);
					return emptyProvider.getConfiguration();
				});
	}

	@Override
	public String getKey() {
		return KEY;
	}

	@Override
	public void install() {
		// Pick the first available node implementing 'service:id' if exists
		final String primary = nodeRepository.findAllBy(" refined.refined.id", "service:id").stream().map(Node::getId)
				.findFirst().orElse("empty");
		log.info("{} will use {} as primary node. You can override this default choice by setting"
				+ " -D{}='service:id:some:node'", getKey(), primary, PRIMARY_CONFIGURATION);
		configuration.put(PRIMARY_CONFIGURATION, primary);
	}

}
