package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Filtro global de API Gateway para propagar los permisos del usuario en la cabecera
 * {@code X-User-Permissions} hacia los microservicios downstream.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@Component
@RequiredArgsConstructor
public class PermissionHeaderFilter implements GlobalFilter, Ordered {

    private final PermissionResolverService permissionResolverService;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        final ServerWebExchange mutatedExchange = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.remove(GatewayConstants.HEADER_USER_PERMISSIONS);
                    h.remove(GatewayConstants.HEADER_USER_ROLES);
                }))
                .build();

        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .flatMap(jwtAuth -> {
                    final List<String> roles = jwtAuth.getToken().getClaimAsStringList(GatewayConstants.CLAIM_ROLES);
                    if (CollectionUtils.isEmpty(roles)) {
                        return chain.filter(mutatedExchange);
                    }

                    final String rolesHeader = String.join(GatewayConstants.DELIMITER_COMMA, roles);

                    return permissionResolverService.getPermissionsForRoles(roles)
                            .defaultIfEmpty(List.of())
                            .flatMap(permissions -> {
                                final String permissionsHeader = CollectionUtils.isEmpty(permissions)
                                        ? null
                                        : String.join(GatewayConstants.DELIMITER_COMMA, permissions);
                                final ServerWebExchange withHeaders = mutatedExchange.mutate()
                                        .request(r -> r.headers(h -> {
                                            h.set(GatewayConstants.HEADER_USER_ROLES, rolesHeader);
                                            if (permissionsHeader != null) {
                                                h.set(GatewayConstants.HEADER_USER_PERMISSIONS, permissionsHeader);
                                            }
                                        }))
                                        .build();
                                return chain.filter(withHeaders);
                            });
                })
                .switchIfEmpty(chain.filter(mutatedExchange));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
