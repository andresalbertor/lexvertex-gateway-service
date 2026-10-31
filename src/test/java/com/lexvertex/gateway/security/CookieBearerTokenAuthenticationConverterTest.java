package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

class CookieBearerTokenAuthenticationConverterTest {

    private final CookieBearerTokenAuthenticationConverter converter =
            new CookieBearerTokenAuthenticationConverter();

    @Test
    void prefersAuthorizationBearerOverCookie() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer from-header")
                        .cookie(new HttpCookie(GatewayConstants.COOKIE_ACCESS_DEFAULT, "from-cookie"))
                        .build());

        final var auth = converter.convert(exchange).block();
        assertThat(auth).isInstanceOf(BearerTokenAuthenticationToken.class);
        assertThat(((BearerTokenAuthenticationToken) auth).getToken()).isEqualTo("from-header");
    }

    @Test
    void fallsBackToAccessCookie() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/")
                        .cookie(new HttpCookie(GatewayConstants.COOKIE_ACCESS_DEFAULT, "cookie-jwt"))
                        .build());

        final var auth = converter.convert(exchange).block();
        assertThat(auth).isInstanceOf(BearerTokenAuthenticationToken.class);
        assertThat(((BearerTokenAuthenticationToken) auth).getToken()).isEqualTo("cookie-jwt");
    }

    @Test
    void emptyWhenNoBearerAndNoCookie() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/").build());
        assertThat(converter.convert(exchange).block()).isNull();
    }
}
