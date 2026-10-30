package com.lexvertex.gateway.repository;

import com.lexvertex.gateway.constant.GatewayConstants;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * Repositorio reactivo R2DBC para la consulta de permisos asociados a roles en el API Gateway.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@Repository
@RequiredArgsConstructor
public class RolePermissionRepository {

    private static final String QUERY_PERMISSIONS_BY_ROLES = """
            SELECT DISTINCT p.code
            FROM role_permission rp
            JOIN permission p ON p.id = rp.permission_id
            JOIN role r ON r.id = rp.role_id
            WHERE r.code IN (:roles)
            """;

    private final DatabaseClient databaseClient;

    /**
     * Consulta de forma reactiva y no bloqueante los códigos de permisos correspondientes a los roles indicados.
     *
     * @param roles lista de códigos de rol
     * @return {@link Mono} con la lista de permisos encontrados
     */
    public Mono<List<String>> findPermissionsByRoleCodes(final List<String> roles) {
        if (CollectionUtils.isEmpty(roles)) {
            return Mono.just(Collections.emptyList());
        }

        return databaseClient.sql(QUERY_PERMISSIONS_BY_ROLES)
                .bind(GatewayConstants.PARAM_ROLES, roles)
                .map(row -> row.get(GatewayConstants.COL_CODE, String.class))
                .all()
                .collectList();
    }
}
