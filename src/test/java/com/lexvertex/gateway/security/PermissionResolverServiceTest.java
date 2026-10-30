package com.lexvertex.gateway.security;

import com.lexvertex.gateway.repository.RolePermissionRepository;
import com.lexvertex.gateway.security.impl.PermissionResolverServiceImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pruebas unitarias para {@link PermissionResolverServiceImpl}.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0
 * @since 2026-10-24
 */
@ExtendWith(MockitoExtension.class)
class PermissionResolverServiceTest {

    @Mock
    private RolePermissionRepository rolePermissionRepository;

    @InjectMocks
    private PermissionResolverServiceImpl permissionResolverService;

    @Test
    @DisplayName("Debe retornar lista vacía si roles es nulo o vacío sin consultar el repositorio")
    void shouldReturnEmptyListWhenRolesIsEmptyOrNull() {
        List<String> nullResult = permissionResolverService.getPermissionsForRoles(null).block();
        List<String> emptyResult = permissionResolverService.getPermissionsForRoles(Collections.emptyList()).block();

        assertThat(nullResult).isNotNull().isEmpty();
        assertThat(emptyResult).isNotNull().isEmpty();
        verify(rolePermissionRepository, never()).findPermissionsByRoleCodes(anyList());
    }

    @Test
    @DisplayName("Debe delegar la consulta de permisos al repositorio reactivo cuando se suministran roles")
    void shouldDelegateToRepositoryWhenRolesAreProvided() {
        List<String> roles = List.of("ADMN", "ABOG");
        List<String> expectedPermissions = List.of("user:read", "client:read");

        when(rolePermissionRepository.findPermissionsByRoleCodes(roles))
                .thenReturn(Mono.just(expectedPermissions));

        List<String> actualPermissions = permissionResolverService.getPermissionsForRoles(roles).block();

        assertThat(actualPermissions).isNotNull().containsExactlyElementsOf(expectedPermissions);
        verify(rolePermissionRepository).findPermissionsByRoleCodes(roles);
    }
}
