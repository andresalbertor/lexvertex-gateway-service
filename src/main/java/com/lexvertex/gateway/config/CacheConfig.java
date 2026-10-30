package com.lexvertex.gateway.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.lexvertex.gateway.constant.GatewayConstants;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/**
 * Configuración del gestor de caché local asíncrono basado en Caffeine para flujos reactivos.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Construye el gestor de caché Caffeine habilitado en modo asíncrono compatible con {@code Mono} y {@code Flux}.
     *
     * @return instancia configurada de {@link CacheManager}
     */
    @Bean
    public CacheManager cacheManager() {
        final CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(GatewayConstants.CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES)
                .maximumSize(GatewayConstants.CACHE_MAX_SIZE));
        cacheManager.setAsyncCacheMode(true);
        return cacheManager;
    }
}
