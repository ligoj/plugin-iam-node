/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.iam;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.dao.NodeRepository;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamConfigurationProvider;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.app.iam.empty.EmptyIamProvider;
import org.ligoj.app.model.Node;
import org.ligoj.app.plugin.id.resource.IdentityServicePlugin;
import org.ligoj.app.resource.ServicePluginLocator;
import org.ligoj.bootstrap.core.plugin.FeaturePlugin;
import org.ligoj.bootstrap.core.security.SecurityHelper;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.ligoj.bootstrap.resource.system.session.ISessionSettingsProvider;
import org.ligoj.bootstrap.resource.system.session.SessionSettings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.cache.annotation.CacheResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Identity and Access Management provider based on node. A primary node is used to fetch user details. The secondary
 * provider can authenticate some users before the primary, when their login is accepted.<br>
 * Without a usable primary node, the fail-safe empty IAM is used: it accepts any credentials, and the administrators
 * are warned through the session settings (see {@link #decorate(SessionSettings)}).
 */
@Component
@Slf4j
@Order(10)
public class NodeBasedIamProvider implements IamProvider, FeaturePlugin, ISessionSettingsProvider {

	private static final String KEY = "feature:iam:node";

	/**
	 * Configuration key for IAM primary node.
	 */
	private static final String PRIMARY_CONFIGURATION = KEY + ":primary";

	/**
	 * Configuration key for IAM secondary node.
	 */
	private static final String SECONDARY_CONFIGURATION = KEY + ":secondary";

	/**
	 * Primary node value selecting the fail-safe empty IAM.
	 */
	private static final String EMPTY_PRIMARY = "empty";

	/**
	 * User settings entry holding the session warnings: a list of <code>{code, parameters}</code> displayed by the UI
	 * with the <code>warning.&lt;code&gt;</code> message.
	 */
	static final String WARNINGS = "warnings";

	@Autowired
	protected ServicePluginLocator locator;

	@Autowired
	protected ConfigurationResource configuration;

	@Autowired
	private NodeRepository nodeRepository;

	@Autowired
	private SecurityHelper securityHelper;

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
				.toList();
	}

	/**
	 * Primary user node.
	 *
	 * @return Primary user node. Never <code>null</code>.
	 */
	protected String getPrimary() {
		return configuration.get(PRIMARY_CONFIGURATION, EMPTY_PRIMARY);
	}

	@Override
	public Authentication authenticate(final Authentication authentication) {

		// Determine the right provider to authenticate among the IAM nodes
		for (final String nodeId : getSecondary()) {
			final IdentityServicePlugin plugin = locator.getResource(nodeId, IdentityServicePlugin.class);
			if (plugin == null) {
				// Ignore IAM provider not found
				log.info("Secondary IAM node '{}' does not exist", nodeId);
			} else if (plugin.accept(authentication, nodeId)) {
				// IAM provider has been found, use it for this authentication
				return plugin.authenticate(authentication, nodeId, false);
			}
		}

		// Primary authentication
		final String primary = getPrimary();
		return Optional.ofNullable(locator.getResource(primary, IdentityServicePlugin.class))
				.map(p -> p.authenticate(authentication, primary, true)).orElseGet(() -> {
					log.info("Primary IAM node '{}' does not exist, use empty IAM", primary);
					return emptyProvider.authenticate(authentication);
				});
	}

	@Override
	public IamConfiguration getConfiguration() {
		self.ensureCachedConfiguration();
		return Optional.ofNullable(iamConfiguration).orElseGet(this::refreshConfiguration);
	}

	/**
	 * Ensure the configuration cache is set.
	 * 
	 * @return Ignored.
	 */
	@CacheResult(cacheName = "iam-node-configuration")
	public boolean ensureCachedConfiguration() {
		refreshConfiguration();
		return true;
	}

	private IamConfiguration refreshConfiguration() {
		// Only one primary node is used for repository configuration
		final String primary = getPrimary();
		return Optional.ofNullable(locator.getResource(primary, IamConfigurationProvider.class))
				.map(p -> p.getConfiguration(primary)).orElseGet(() -> {
					// Node or related plug-in are not available
					log.error("Primary IAM node '{}' does not exist, use empty IAM", primary);
					return emptyProvider.getConfiguration();
				});
	}

	/**
	 * Warn the administrators when the primary node is not usable: undefined, explicitly {@value #EMPTY_PRIMARY}, or not
	 * resolved to an IAM plug-in. The fail-safe empty IAM is then used, accepting any login and password. The regular
	 * users are not told: they cannot fix it.
	 */
	@Override
	public void decorate(final SessionSettings settings) {
		if (!securityHelper.isAdmin()) {
			return;
		}
		final var primary = StringUtils.trimToNull(configuration.get(PRIMARY_CONFIGURATION));
		if (primary == null || EMPTY_PRIMARY.equals(primary)) {
			addWarning(settings, "iam-node-no-primary", Map.of());
		} else if (locator.getResource(primary, IamConfigurationProvider.class) == null) {
			addWarning(settings, "iam-node-primary-not-found", Map.of("primary", primary));
		}
	}

	@SuppressWarnings("unchecked")
	private void addWarning(final SessionSettings settings, final String code, final Map<String, String> parameters) {
		((List<Object>) settings.getUserSettings().computeIfAbsent(WARNINGS, k -> new ArrayList<>()))
				.add(Map.of("code", code, "parameters", parameters));
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
