/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.iam;

import java.util.function.Function;

import org.ligoj.bootstrap.resource.system.cache.CacheManagerAware;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Role;
import org.springframework.stereotype.Component;

import com.hazelcast.cache.HazelcastCacheManager;
import com.hazelcast.config.CacheConfig;

/**
 * Cache management for this plug-in
 */
@Component
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class IamNodeCache implements CacheManagerAware {

	@Override
	public void onCreate(final HazelcastCacheManager cacheManager,
			final Function<String, CacheConfig<?, ?>> provider) {
		cacheManager.createCache("iam-node-configuration", provider.apply("iam-node-configuration"));
	}

}
