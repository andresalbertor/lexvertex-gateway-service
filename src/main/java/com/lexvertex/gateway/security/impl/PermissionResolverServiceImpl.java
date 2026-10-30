package com.lexvertex.gateway.security.impl;

import com.lexvertex.gateway.constant.GatewayConstants;
import com.lexvertex.gateway.repository.RolePermissionRepository;
import com.lexvertex.gateway.security.PermissionResolverService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * Implementación reactiva para la resolución de permisos asignados a roles con cacheo Caffeine.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@Service
@RequiredArgsConstructor
public class PermissionResolverServiceImpl implements PermissionResolverService {

    private final RolePermissionRepository rolePermissionRepository;

    @Override
    @Cacheable(value = GatewayConstants.CACHE_ROLE_PERMISSIONS, key = GatewayConstants.CACHE_KEY_ROLES)
    public Mono<List<String>> getPermissionsForRoles(final List<String> roles) {
        if (CollectionUtils.isEmpty(roles)) {
            return Mono.just(Collections.emptyList());
        }

        return rolePermissionRepository.findPermissionsByRoleCodes(roles)
                .cache();
    }
}
