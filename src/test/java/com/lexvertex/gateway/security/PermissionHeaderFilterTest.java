package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PermissionHeaderFilterTest {

    @Mock
    private PermissionResolverService permissionResolverService;

    private final AtomicInteger chainCalls = new AtomicInteger();

    private PermissionHeaderFilter filter() {
        return new PermissionHeaderFilter(permissionResolverService);
    }

    private static MockServerWebExchange exchangeWithSpoofedHeaders() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/x")
                .header(GatewayConstants.HEADER_USER_PERMISSIONS, "spoofed:permission")
                .header(GatewayConstants.HEADER_USER_ROLES, "SPOOFED")
                .build());
    }

    private static JwtAuthenticationToken jwtAuth(final List<String> rolesClaim, final List<String> authorities) {
        final Jwt.Builder builder = Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject("u")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (rolesClaim != null) {
            builder.claim(GatewayConstants.CLAIM_ROLES, rolesClaim);
        } else {
            builder.claim("dummy", "x");
        }
        final List<SimpleGrantedAuthority> granted = new ArrayList<>();
        authorities.forEach(a -> granted.add(new SimpleGrantedAuthority(a)));
        return new JwtAuthenticationToken(builder.build(), granted);
    }

    private Mono<Void> run(final ServerWebExchange exchange, final AtomicReference<ServerWebExchange> captured,
                           final org.springframework.security.core.Authentication auth) {
        final GatewayFilterChain chain = e -> {
            chainCalls.incrementAndGet();
            captured.set(e);
            return Mono.empty();
        };
        final Mono<Void> result = filter().filter(exchange, chain);
        return auth == null
                ? result
                : result.contextWrite(ReactiveSecurityContextHolder
                        .withSecurityContext(Mono.just(new SecurityContextImpl(auth))));
    }

    @Test
    void orderIsLowestPrecedence() {
        assertThat(filter().getOrder()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
    }

    @Test
    void stripsSpoofedHeadersWhenNoAuthentication() {
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured, null).block();

        assertThat(captured.get().getRequest().getHeaders().containsHeader(GatewayConstants.HEADER_USER_PERMISSIONS))
                .isFalse();
        assertThat(captured.get().getRequest().getHeaders().containsHeader(GatewayConstants.HEADER_USER_ROLES))
                .isFalse();
        assertThat(chainCalls.get()).isEqualTo(1);
        verifyNoInteractions(permissionResolverService);
    }

    @Test
    void stripsHeadersWhenAuthenticationIsNotJwt() {
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        final var auth = new UsernamePasswordAuthenticationToken("u", "p", List.of());

        run(exchangeWithSpoofedHeaders(), captured, auth).block();

        assertThat(captured.get().getRequest().getHeaders().containsHeader(GatewayConstants.HEADER_USER_ROLES))
                .isFalse();
        assertThat(chainCalls.get()).isEqualTo(1);
        verifyNoInteractions(permissionResolverService);
    }

    @Test
    void injectsRolesAndPermissionsFromJwtClaim() {
        final List<String> roles = List.of("ADMN", "ABOG");
        when(permissionResolverService.getPermissionsForRoles(roles))
                .thenReturn(Mono.just(List.of("client:read", "client:update")));
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured, jwtAuth(roles, List.of())).block();

        final var headers = captured.get().getRequest().getHeaders();
        assertThat(chainCalls.get()).isEqualTo(1);
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_ROLES)).isEqualTo("ADMN,ABOG");
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_PERMISSIONS))
                .isEqualTo("client:read,client:update");
    }

    @Test
    void fallsBackToRolePrefixedAuthoritiesWhenClaimMissing() {
        final List<String> expected = List.of("ADMN");
        when(permissionResolverService.getPermissionsForRoles(expected))
                .thenReturn(Mono.just(List.of("organization:read")));
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured,
                jwtAuth(null, List.of("ROLE_ADMN", "ROLE_ADMN", "client:read"))).block();

        final var headers = captured.get().getRequest().getHeaders();
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_ROLES)).isEqualTo("ADMN");
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_PERMISSIONS)).isEqualTo("organization:read");
    }

    @Test
    void continuesWithoutHeadersWhenNoRolesResolved() {
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured, jwtAuth(List.of(), List.of("client:read"))).block();

        assertThat(captured.get()).isNotNull();
        assertThat(captured.get().getRequest().getHeaders().containsHeader(GatewayConstants.HEADER_USER_ROLES))
                .isFalse();
        verify(permissionResolverService, never()).getPermissionsForRoles(org.mockito.ArgumentMatchers.anyList());
    }

    @Test
    void omitsPermissionsHeaderWhenResolverReturnsEmptyList() {
        final List<String> roles = List.of("ABOG");
        when(permissionResolverService.getPermissionsForRoles(roles)).thenReturn(Mono.just(List.of()));
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured, jwtAuth(roles, List.of())).block();

        final var headers = captured.get().getRequest().getHeaders();
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_ROLES)).isEqualTo("ABOG");
        assertThat(headers.containsHeader(GatewayConstants.HEADER_USER_PERMISSIONS)).isFalse();
    }

    @Test
    void omitsPermissionsHeaderWhenResolverReturnsEmptyMono() {
        final List<String> roles = List.of("ABOG");
        when(permissionResolverService.getPermissionsForRoles(roles)).thenReturn(Mono.empty());
        final AtomicReference<ServerWebExchange> captured = new AtomicReference<>();

        run(exchangeWithSpoofedHeaders(), captured, jwtAuth(roles, List.of())).block();

        final var headers = captured.get().getRequest().getHeaders();
        assertThat(headers.getFirst(GatewayConstants.HEADER_USER_ROLES)).isEqualTo("ABOG");
        assertThat(headers.containsHeader(GatewayConstants.HEADER_USER_PERMISSIONS)).isFalse();
    }
}
