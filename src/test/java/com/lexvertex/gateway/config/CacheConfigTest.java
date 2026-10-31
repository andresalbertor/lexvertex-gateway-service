package com.lexvertex.gateway.config;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;

class CacheConfigTest {

    @Test
    void cacheManagerIsAsyncCaffeineCacheManager() {
        final CacheManager manager = new CacheConfig().cacheManager();

        assertThat(manager).isInstanceOf(CaffeineCacheManager.class);
        final CaffeineCacheManager caffeine = (CaffeineCacheManager) manager;
                assertThat(caffeine.getCache(GatewayConstants.CACHE_ROLE_PERMISSIONS))
                .isNotNull()
                .extracting(c -> c.getNativeCache().getClass().getName())
                .asString()
                .contains("LocalAsyncCache");
        assertThat(caffeine.getCacheNames()).contains(GatewayConstants.CACHE_ROLE_PERMISSIONS);
    }
}
