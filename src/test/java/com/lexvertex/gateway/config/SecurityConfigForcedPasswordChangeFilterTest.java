package com.lexvertex.gateway.config;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigForcedPasswordChangeFilterTest {

    private static final String TARGET = "https://sso.example.test/profile/security";

    private final SecurityConfig securityConfig = new SecurityConfig();
    private final WebFilter filter = securityConfig.forcedPasswordChangeFilter(TARGET);

    private static JwtAuthenticationToken jwtAuth(final Boolean mustChange) {
        final Jwt.Builder builder = Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject("u")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (mustChange != null) {
            builder.claim(GatewayConstants.CLAIM_MUST_CHANGE_PASSWORD, mustChange);
        } else {
            builder.claim("dummy", "x");
        }
        return new JwtAuthenticationToken(builder.build(), List.of());
    }

    private boolean runAndReportChainCalled(final ServerWebExchange exchange, final WebFilter webFilter) {
        final AtomicBoolean called = new AtomicBoolean(false);
        final WebFilterChain chain = e -> {
            called.set(true);
            return Mono.empty();
        };
        webFilter.filter(exchange, chain).block();
        return called.get();
    }

    private ServerWebExchange withPrincipal(final String uri, final String accept, final String host,
                                            final Authentication principal) {
        final MockServerHttpRequest.BaseBuilder<?> req = MockServerHttpRequest.get(uri);
        if (accept != null) {
            req.header(HttpHeaders.ACCEPT, accept);
        }
        if (host != null) {
            req.header(GatewayConstants.HEADER_HOST, host);
        }
        final ServerWebExchange base = MockServerWebExchange.from(req.build());
        return principal == null ? base : base.mutate().principal(Mono.just(principal)).build();
    }

    @Test
    void passesThroughWhenNoPrincipal() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", null, null, null);

        assertThat(runAndReportChainCalled(ex, filter)).isTrue();
        assertThat(ex.getResponse().getStatusCode()).isNull();
    }

    @Test
    void passesThroughWhenPrincipalIsNotJwt() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", null, null,
                new UsernamePasswordAuthenticationToken("u", "p", List.of()));

        assertThat(runAndReportChainCalled(ex, filter)).isTrue();
    }

    @Test
    void passesThroughWhenMustChangeClaimAbsent() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", MediaType.TEXT_HTML_VALUE, null, jwtAuth(null));

        assertThat(runAndReportChainCalled(ex, filter)).isTrue();
    }

    @Test
    void passesThroughWhenMustChangeFalse() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", MediaType.TEXT_HTML_VALUE, null,
                jwtAuth(false));

        assertThat(runAndReportChainCalled(ex, filter)).isTrue();
    }

    @Test
    void allowsPasswordChangeLogoutRefreshAndProfileSecurityPaths() {
        for (final String path : List.of(
                GatewayConstants.PATH_AUTH_PASSWORD_CHANGE,
                GatewayConstants.PATH_AUTH_LOGOUT,
                GatewayConstants.PATH_AUTH_REFRESH,
                GatewayConstants.PATH_PROFILE_SECURITY,
                GatewayConstants.PATH_PROFILE_SECURITY + "/mfa")) {
            final ServerWebExchange ex = withPrincipal(path, MediaType.TEXT_HTML_VALUE, null, jwtAuth(true));

            assertThat(runAndReportChainCalled(ex, filter)).as(path).isTrue();
            assertThat(ex.getResponse().getStatusCode()).as(path).isNull();
        }
    }

    @Test
    void redirectsHtmlNavigationWhenMustChange() {
        final ServerWebExchange ex = withPrincipal("/dashboard", MediaType.TEXT_HTML_VALUE, null, jwtAuth(true));

        assertThat(runAndReportChainCalled(ex, filter)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(ex.getResponse().getHeaders().getLocation()).isEqualTo(URI.create(TARGET));
    }

    @Test
    void redirectsWhenAcceptMissingOrWildcard() {
        for (final String accept : new String[]{null, "", "*/*", "text/*", "application/json, text/html"}) {
            final ServerWebExchange ex = withPrincipal("/dashboard", accept, null, jwtAuth(true));

            assertThat(runAndReportChainCalled(ex, filter)).as("accept=" + accept).isFalse();
            assertThat(ex.getResponse().getStatusCode()).as("accept=" + accept).isEqualTo(HttpStatus.FOUND);
        }
    }

    @Test
    void forbidsJsonApiClientsWhenMustChange() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", MediaType.APPLICATION_JSON_VALUE, null,
                jwtAuth(true));

        assertThat(runAndReportChainCalled(ex, filter)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.getResponse().getHeaders().getLocation()).isNull();
    }

    @Test
    void forbidsNonHtmlNonWildcardAccept() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", "application/xml", null, jwtAuth(true));

        assertThat(runAndReportChainCalled(ex, filter)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void alwaysRedirectsOnVigilisHostEvenForJson() {
        final ServerWebExchange ex = withPrincipal("/api/v1/clients", MediaType.APPLICATION_JSON_VALUE,
                GatewayConstants.VIGILIS_HOST, jwtAuth(true));

        assertThat(runAndReportChainCalled(ex, filter)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(ex.getResponse().getHeaders().getLocation()).isEqualTo(URI.create(TARGET));
    }

    @Test
    void alwaysRedirectsOnVigilisPathEvenForJson() {
        final ServerWebExchange ex = withPrincipal(GatewayConstants.PATH_VIGILIS_PREFIX + "/view",
                MediaType.APPLICATION_JSON_VALUE, null, jwtAuth(true));

        assertThat(runAndReportChainCalled(ex, filter)).isFalse();
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    @Test
    void usesDefaultTargetWhenConfiguredUrlBlankOrNull() {
        for (final String configured : new String[]{null, "  "}) {
            final WebFilter defaulted = securityConfig.forcedPasswordChangeFilter(configured);
            final ServerWebExchange ex = withPrincipal("/dashboard", MediaType.TEXT_HTML_VALUE, null, jwtAuth(true));

            runAndReportChainCalled(ex, defaulted);

            assertThat(ex.getResponse().getHeaders().getLocation())
                    .isEqualTo(URI.create(GatewayConstants.LEXVERTEX_PASSWORD_CHANGE_URL));
        }
    }

    @Test
    void trimsConfiguredTarget() {
        final WebFilter trimmed = securityConfig.forcedPasswordChangeFilter("  " + TARGET + "  ");
        final ServerWebExchange ex = withPrincipal("/dashboard", MediaType.TEXT_HTML_VALUE, null, jwtAuth(true));

        runAndReportChainCalled(ex, trimmed);

        assertThat(ex.getResponse().getHeaders().getLocation()).isEqualTo(URI.create(TARGET));
    }

    @Test
    void corsConfigurationUsesProvidedOriginsAndGatewayDefaults() {
        final CorsConfigurationSource source = securityConfig.corsConfigurationSource(
                List.of("https://app.example.test"));
        final MockServerWebExchange ex = MockServerWebExchange.from(
                MockServerHttpRequest.method(HttpMethod.GET, "/api/v1/anything").build());

        final CorsConfiguration cors = source.getCorsConfiguration(ex);

        assertThat(cors).isNotNull();
        assertThat(cors.getAllowedOrigins()).containsExactly("https://app.example.test");
        assertThat(cors.getAllowedMethods()).containsExactlyElementsOf(GatewayConstants.CORS_ALLOWED_METHODS);
        assertThat(cors.getAllowedHeaders()).containsExactlyElementsOf(GatewayConstants.CORS_ALLOWED_HEADERS);
        assertThat(cors.getAllowCredentials()).isTrue();
        assertThat(cors.getMaxAge()).isEqualTo(GatewayConstants.CORS_MAX_AGE_SECONDS);
    }
}

