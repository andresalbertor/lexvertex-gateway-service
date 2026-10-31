package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Extrae el JWT del header {@code Authorization: Bearer} o, si falta, de la cookie {@code lex_access}
 * usada para SSO hacia Vigilís y otros hosts del mismo dominio.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-10-30
 */
@Component
public class CookieBearerTokenAuthenticationConverter implements ServerAuthenticationConverter {

    private final ServerBearerTokenAuthenticationConverter bearerConverter =
            new ServerBearerTokenAuthenticationConverter();

    @Override
    public Mono<Authentication> convert(final ServerWebExchange exchange) {
        return bearerConverter.convert(exchange)
                .switchIfEmpty(Mono.defer(() -> fromAccessCookie(exchange)));
    }

    private Mono<Authentication> fromAccessCookie(final ServerWebExchange exchange) {
        final HttpCookie cookie = exchange.getRequest().getCookies()
                .getFirst(GatewayConstants.COOKIE_ACCESS_DEFAULT);
        if (cookie == null || StringUtils.isBlank(cookie.getValue())) {
            return Mono.empty();
        }
        return Mono.just(new BearerTokenAuthenticationToken(cookie.getValue()));
    }
}
