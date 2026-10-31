package com.lexvertex.gateway.config;

import com.lexvertex.gateway.constant.GatewayConstants;
import com.lexvertex.gateway.security.CookieBearerTokenAuthenticationConverter;
import com.lexvertex.gateway.security.VigilisAuthenticationEntryPoint;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Configuración de seguridad reactiva WebFlux, validación OAuth2 JWT y políticas CORS del API Gateway.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Configura la cadena de filtros de seguridad reactiva definiendo rutas públicas y servidor de recursos JWT.
     *
     * @param http               configurador reactivo de seguridad HTTP
     * @param bearerConverter    Authorization Bearer o cookie {@code lex_access}
     * @param vigilisEntryPoint  redirect SSO HTML hacia login de Lex Vertex en host Vigilís
     * @return cadena reactiva {@link SecurityWebFilterChain} construida
     */
    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            final ServerHttpSecurity http,
            final CookieBearerTokenAuthenticationConverter bearerConverter,
            final VigilisAuthenticationEntryPoint vigilisEntryPoint
    ) {
        http
                .cors(Customizer.withDefaults())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(vigilisEntryPoint))
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS, GatewayConstants.PATH_ALL).permitAll()
                        .pathMatchers(GatewayConstants.PUBLIC_PATHS).permitAll()
                        .pathMatchers(GatewayConstants.PATH_ACTUATOR_GATEWAY)
                        .hasRole(GatewayConstants.ROLE_ADMIN)
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenConverter(bearerConverter)
                        .authenticationEntryPoint(vigilisEntryPoint)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    /**
     * Bloquea el resto de rutas cuando el JWT exige cambio de contraseña.
     * En Vigilís (host o path) redirige siempre (302) a la pantalla de seguridad;
     * en otros hosts el 302 aplica a navegación HTML y el 403 a clientes API.
     *
     * @param passwordChangeUrl URL de cambio de contraseña ({@code app.sso.password-change-url})
     * @return instancia reactiva de {@link WebFilter}
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE - 10)
    WebFilter forcedPasswordChangeFilter(
            @Value("${app.sso.password-change-url:" + GatewayConstants.LEXVERTEX_PASSWORD_CHANGE_URL + "}")
            final String passwordChangeUrl
    ) {
        final String target = passwordChangeUrl == null || passwordChangeUrl.isBlank()
                ? GatewayConstants.LEXVERTEX_PASSWORD_CHANGE_URL
                : passwordChangeUrl.trim();
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .filter(authentication -> isBlockedByForcedPasswordChange(authentication, exchange))
                .map(authentication -> Boolean.TRUE)
                .defaultIfEmpty(Boolean.FALSE)
                .flatMap(blocked -> blocked ? rejectPendingPasswordChange(exchange, target) : chain.filter(exchange));
    }

    private static boolean isBlockedByForcedPasswordChange(
            final JwtAuthenticationToken authentication,
            final ServerWebExchange exchange
    ) {
        final boolean mustChange = Boolean.TRUE.equals(
                authentication.getToken().getClaim(GatewayConstants.CLAIM_MUST_CHANGE_PASSWORD));
        final String path = exchange.getRequest().getPath().value();
        final boolean allowed = Strings.CS.equals(path, GatewayConstants.PATH_AUTH_PASSWORD_CHANGE)
                || Strings.CS.equals(path, GatewayConstants.PATH_AUTH_LOGOUT)
                || Strings.CS.equals(path, GatewayConstants.PATH_AUTH_REFRESH)
                || Strings.CS.startsWith(path, GatewayConstants.PATH_PROFILE_SECURITY);
        return mustChange && !allowed;
    }

    private static Mono<Void> rejectPendingPasswordChange(final ServerWebExchange exchange, final String target) {
        final HttpHeaders headers = exchange.getRequest().getHeaders();
        if (VigilisAuthenticationEntryPoint.isVigilisRequest(exchange.getRequest())
                || wantsHtmlNavigation(headers)) {
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().setLocation(URI.create(target));
            return exchange.getResponse().setComplete();
        }
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }
    private static boolean wantsHtmlNavigation(final HttpHeaders headers) {
        final String accept = headers.getFirst(HttpHeaders.ACCEPT);
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

    /**
     * Construye el convertidor reactivo que transforma los claims {@code roles} y {@code permissions}
     * del token JWT en autoridades de Spring Security.
     *
     * @return convertidor reactivo de {@link Jwt} hacia {@link AbstractAuthenticationToken}
     */
    @Bean
    Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        final JwtAuthenticationConverter delegate = new JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(jwt -> {
            final Collection<GrantedAuthority> authorities = new ArrayList<>();
            final List<String> roles = jwt.getClaimAsStringList(GatewayConstants.CLAIM_ROLES);
            if (CollectionUtils.isNotEmpty(roles)) {
                roles.forEach(role -> authorities.add(
                        new SimpleGrantedAuthority(GatewayConstants.ROLE_PREFIX + role)));
            }
            final List<String> permissions = jwt.getClaimAsStringList(GatewayConstants.CLAIM_PERMISSIONS);
            if (CollectionUtils.isNotEmpty(permissions)) {
                permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
            }
            return authorities;
        });
        return new ReactiveJwtAuthenticationConverterAdapter(delegate);
    }

    /**
     * Configura el origen reactivo de políticas CORS parametrizado según los orígenes permitidos del entorno.
     *
     * @param allowedOrigins lista de orígenes permitidos inyectada desde configuración
     * @return fuente reactiva {@link CorsConfigurationSource}
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins:" + GatewayConstants.CORS_DEFAULT_ORIGINS + "}")
            final List<String> allowedOrigins
    ) {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(GatewayConstants.CORS_ALLOWED_METHODS);
        configuration.setAllowedHeaders(GatewayConstants.CORS_ALLOWED_HEADERS);
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(GatewayConstants.CORS_MAX_AGE_SECONDS);
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(GatewayConstants.PATH_ALL, configuration);
        return source;
    }
}
