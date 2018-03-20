package org.ligoj.app.plugin.iam;

import java.util.List;
import java.util.Optional;

import javax.cache.annotation.CacheResult;

import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.api.FeaturePlugin;
import org.ligoj.app.api.PluginException;
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
	/**
	 * Configuration key for IAM primary node.
	 */
	private static final String PRIMARY_CONFIGURATION = "iam.primary";

	/**
	 * Configuration key for IAM secondary node.
	 */
	private static final String SECONDARY_CONFIGURATION = "iam.secondary";

	@Autowired
	protected ServicePluginLocator servicePluginLocator;

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
	private EmptyIamProvider emptyProvider;

	private IamConfiguration iamConfiguration;

	/**
	 * Secondary user nodes.
	 * 
	 * @return Secondary user nodes. May be empty.
	 */
	protected String[] getSecondary() {
		return StringUtils.defaultString(configuration.get(SECONDARY_CONFIGURATION), "").split(",");
	}

	/**
	 * Secondary user nodes.
	 * 
	 * @return Secondary user nodes. Should not be <code>null</code>.
	 */
	protected String getPrimary() {
		return configuration.get(PRIMARY_CONFIGURATION);
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
		iamConfiguration = Optional
				.ofNullable(servicePluginLocator.getResource(primary, IamConfigurationProvider.class))
				.map(p -> p.getConfiguration(primary)).orElseGet(() -> {
					// Node or related plug-in are not available
					log.error("Primary node {} is not available, use empty IAM", primary);
					return emptyProvider.getConfiguration();
				});
		return iamConfiguration;
	}

	@Override
	public String getKey() {
		return "feature:iam:node";
	}

	@Override
	public void install() {
		List<Node> nodes = nodeRepository.findAllBy(" refined.refined.id", "service:id");
		if (nodes.isEmpty()) {
			// No available 'id' node
			throw new PluginException(getKey(), "Expects at least one node implementing 'service:id'");
		}

		// At least one node found, use it as default
		final String primary = nodes.get(0).getId();
		log.info("{} will use {} as primary node. You can override this default choice by setting"
				+ " -D{}='service:id:some:node'", getKey(), primary, PRIMARY_CONFIGURATION);
		configuration.saveOrUpdate(PRIMARY_CONFIGURATION, primary);
	}

}
