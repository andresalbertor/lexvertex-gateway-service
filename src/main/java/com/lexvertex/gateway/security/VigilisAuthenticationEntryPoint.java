package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.apache.commons.lang3.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Ante 401 en el host/path de Vigilís: redirige navegadores HTML al login de Lex Vertex
 * con {@code redirect_uri} hacia la URL solicitada; clientes API reciben 401.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.1.0
 * @since 2026-10-30
 */
@Component
public class VigilisAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final String loginUrl;

    public VigilisAuthenticationEntryPoint(
            @Value("${app.sso.login-url:" + GatewayConstants.LEXVERTEX_LOGIN_URL + "}")
            final String loginUrl
    ) {
        this.loginUrl = loginUrl == null || loginUrl.isBlank()
                ? GatewayConstants.LEXVERTEX_LOGIN_URL
                : loginUrl.trim();
    }

    @Override
    public Mono<Void> commence(final ServerWebExchange exchange, final AuthenticationException ex) {
        if (!isVigilisRequest(exchange.getRequest()) || !wantsHtml(exchange.getRequest())) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        final String redirectTarget = buildRequestUrl(exchange.getRequest());
        final URI loginUri = UriComponentsBuilder
                .fromUriString(loginUrl)
                .queryParam(GatewayConstants.QUERY_REDIRECT_URI, redirectTarget)
                .encode()
                .build()
                .toUri();

        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().setLocation(loginUri);
        return exchange.getResponse().setComplete();
    }

    public static boolean isVigilisRequest(final ServerHttpRequest request) {
        final String host = request.getHeaders().getFirst(GatewayConstants.HEADER_HOST);
        if (host != null) {
            final String hostOnly = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
            if (Strings.CI.startsWith(hostOnly, GatewayConstants.VIGILIS_HOST)
                    || Strings.CI.equals(hostOnly, GatewayConstants.VIGILIS_HOST_LOCAL)) {
                return true;
            }
        }
        final String path = request.getURI().getRawPath();
        return path != null && (
                Strings.CS.equals(path, GatewayConstants.PATH_VIGILIS_PREFIX)
                        || Strings.CS.startsWith(path, GatewayConstants.PATH_VIGILIS_PREFIX + "/"));
    }

    private static boolean wantsHtml(final ServerHttpRequest request) {
        final String accept = request.getHeaders().getFirst(HttpHeaders.ACCEPT);
        if (accept == null || accept.isBlank()) {
            return true;
        }
        final String lower = accept.toLowerCase();
        if (lower.contains(MediaType.APPLICATION_JSON_VALUE) && !lower.contains(MediaType.TEXT_HTML_VALUE)) {
            return false;
        }
        return lower.contains(MediaType.TEXT_HTML_VALUE)
                || lower.contains("*/*")
                || lower.contains("text/*");
    }

    private static String buildRequestUrl(final ServerHttpRequest request) {
        final String forwardedProto = request.getHeaders().getFirst("X-Forwarded-Proto");
        final String forwardedHost = request.getHeaders().getFirst("X-Forwarded-Host");
        final String scheme = StringUtilsOrDefault(forwardedProto, request.getURI().getScheme());
        final String host = StringUtilsOrDefault(forwardedHost, request.getHeaders().getFirst(GatewayConstants.HEADER_HOST));
        final String path = request.getURI().getRawPath() == null ? "/" : request.getURI().getRawPath();
        final String query = request.getURI().getRawQuery();
        final StringBuilder url = new StringBuilder(64)
                .append(scheme)
                .append("://")
                .append(host == null ? GatewayConstants.VIGILIS_HOST : host)
                .append(path);
        if (query != null && !query.isBlank()) {
            url.append('?').append(query);
        }
        return url.toString();
    }

    private static String StringUtilsOrDefault(final String value, final String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
