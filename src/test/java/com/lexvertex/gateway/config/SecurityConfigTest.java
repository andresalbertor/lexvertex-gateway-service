package com.lexvertex.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {

    private final SecurityConfig securityConfig = new SecurityConfig();

    @Test
    void mapsOrganizationPermissionForAdministrator() {
        Authentication authentication = converter().convert(jwt(List.of("ADMN"), List.of(
                "organization:read", "organization:update"
        ))).block();

        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .contains("organization:read", "organization:update", "ROLE_ADMN");
    }

    @Test
    void doesNotGrantOrganizationPermissionWhenClaimIsAbsent() {
        Authentication authentication = converter().convert(jwt(List.of("ABOG"), List.of(
                "client:read"
        ))).block();

        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .doesNotContain("organization:update");
    }

    private Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> converter() {
        return securityConfig.jwtAuthenticationConverter();
    }

    private Jwt jwt(List<String> roles, List<String> permissions) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900))
                .claim("roles", roles)
                .claim("permissions", permissions)
                .build();
    }
}
