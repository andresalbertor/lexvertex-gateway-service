package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AccessCookieAuthorizationWebFilterTest {

    private final AccessCookieAuthorizationWebFilter filter = new AccessCookieAuthorizationWebFilter();

    @Test
    void copiesAccessCookieToAuthorizationWhenMissing() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/")
                        .cookie(new HttpCookie(GatewayConstants.COOKIE_ACCESS_DEFAULT, "jwt-value"))
                        .build());
        final AtomicReference<String> auth = new AtomicReference<>();
        final WebFilterChain chain = e -> {
            auth.set(e.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(auth.get()).isEqualTo("Bearer jwt-value");
    }

    @Test
    void keepsExistingAuthorization() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer from-header")
                        .cookie(new HttpCookie(GatewayConstants.COOKIE_ACCESS_DEFAULT, "from-cookie"))
                        .build());
        final AtomicReference<String> auth = new AtomicReference<>();
        final WebFilterChain chain = e -> {
            auth.set(e.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(auth.get()).isEqualTo("Bearer from-header");
    }
}
