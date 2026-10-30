package com.lexvertex.gateway.security;

import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Contrato del servicio reactivo para resolver los permisos asignados a una lista de roles.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0
 * @since 2026-10-24
 */
public interface PermissionResolverService {

    /**
     * Obtiene los permisos asociados a los roles recibidos de manera reactiva.
     *
     * @param roles lista de nombres de rol.
     * @return {@link Mono} con la lista de permisos.
     */
    Mono<List<String>> getPermissionsForRoles(List<String> roles);
}
