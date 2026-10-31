package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * WebFilter anterior a Spring Security: si no hay {@code Authorization}, copia
 * {@code lex_access} a {@code Authorization: Bearer …} para navegación HTML (Vigilís).
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-10-31
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AccessCookieAuthorizationWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final WebFilterChain chain) {
        final String existing = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isNotBlank(existing)) {
            return chain.filter(exchange);
        }

        final HttpCookie cookie = exchange.getRequest().getCookies()
                .getFirst(GatewayConstants.COOKIE_ACCESS_DEFAULT);
        if (cookie == null || StringUtils.isBlank(cookie.getValue())) {
            return chain.filter(exchange);
        }

        final ServerHttpRequest request = exchange.getRequest().mutate()
                .header(
                        HttpHeaders.AUTHORIZATION,
                        GatewayConstants.TOKEN_SCHEME_BEARER + " " + cookie.getValue().trim())
                .build();
        return chain.filter(exchange.mutate().request(request).build());
    }
}
