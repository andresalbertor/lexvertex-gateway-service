package com.lexvertex.gateway.security;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;

class VigilisAuthenticationEntryPointTest {

    private final VigilisAuthenticationEntryPoint entryPoint =
            new VigilisAuthenticationEntryPoint(GatewayConstants.LEXVERTEX_LOGIN_URL);

    @Test
    void redirectsHtmlOnVigilisHost() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://vigilis.lexvertex.cloud/view/")
                        .header(GatewayConstants.HEADER_HOST, GatewayConstants.VIGILIS_HOST)
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        entryPoint.commence(exchange, new BadCredentialsException("no auth")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation())
                .isNotNull()
                .hasHost("www.lexvertex.cloud")
                .hasPath("/login");
        assertThat(exchange.getResponse().getHeaders().getLocation().getQuery())
                .contains("redirect_uri=")
                .contains("vigilis.lexvertex.cloud");
    }

    @Test
    void redirectsHtmlOnLocalVigilisPath() {
        final VigilisAuthenticationEntryPoint localEntry =
                new VigilisAuthenticationEntryPoint("http://localhost:8089/login");
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/vigilis/dashboard")
                        .header(GatewayConstants.HEADER_HOST, "localhost:8080")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        localEntry.commence(exchange, new BadCredentialsException("no auth")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation())
                .isNotNull()
                .hasHost("localhost")
                .hasPath("/login");
    }

    @Test
    void returnsUnauthorizedForApiClientsOnVigilis() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://vigilis.lexvertex.cloud/api/v1/x")
                        .header(GatewayConstants.HEADER_HOST, GatewayConstants.VIGILIS_HOST)
                        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                        .build());

        entryPoint.commence(exchange, new BadCredentialsException("no auth")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
    }

    @Test
    void returnsUnauthorizedOnOtherHosts() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://api.lexvertex.cloud/api/v1/users")
                        .header(GatewayConstants.HEADER_HOST, "api.lexvertex.cloud")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        entryPoint.commence(exchange, new BadCredentialsException("no auth")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
