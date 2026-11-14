package com.lexvertex.gateway.error;

import com.lexvertex.gateway.constant.GatewayConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GatewayErrorWebExceptionHandlerTest {

    private GatewayErrorWebExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GatewayErrorWebExceptionHandler(new DefaultResourceLoader());
    }

    @Test
    void rendersBrandedHtmlForBrowserAccept() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/vigilis/view/")
                        .header(GatewayConstants.HEADER_HOST, "localhost:8080")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        handler.handle(exchange, new RuntimeException("boom")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8));

        final String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body)
                .isNotNull()
                .contains("Lex Vertex")
                .contains("LEX VERTEX")
                .contains("Sistema de Gestión Jurídica")
                .contains("Error 500")
                .contains(">Inicio</a>")
                .contains("href=\"" + GatewayConstants.PATH_HOME + "\"")
                .doesNotContain("Whitelabel")
                .doesNotContain("Vigilis")
                .doesNotContain("boom");
    }

    @Test
    void linksInicioToDomainRootOnVigilisHost() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://vigilis.lexvertex.cloud/view/")
                        .header(GatewayConstants.HEADER_HOST, GatewayConstants.VIGILIS_HOST)
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        handler.handle(exchange, new ConnectException("refused")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        final String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body)
                .contains("Error 503")
                .contains(">Inicio</a>")
                .contains("href=\"" + GatewayConstants.PATH_HOME + "\"");
    }

    @Test
    void returnsJsonForApiAccept() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/vigilis/view/")
                        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                        .build());

        handler.handle(exchange, new RuntimeException("secret")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.APPLICATION_JSON);

        final String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body)
                .isNotNull()
                .startsWith("{")
                .contains("\"status\":500")
                .doesNotContain("<html")
                .doesNotContain("secret");
    }

    @Test
    void returnsJsonForApiPathEvenWithHtmlAccept() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/api/v1/health")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        handler.handle(exchange, new ResponseStatusException(HttpStatus.BAD_GATEWAY, "upstream")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        final String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body)
                .contains("\"status\":502")
                .doesNotContain("<html");
    }

    @Test
    void mapsTimeoutToGatewayTimeoutHtml() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());

        handler.handle(exchange, new TimeoutException("slow")).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.GATEWAY_TIMEOUT);
        final String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body)
                .contains("Error 504")
                .contains(GatewayConstants.PATH_HOME)
                .contains("Tiempo de espera agotado");
    }

    @Test
    void propagatesWhenResponseAlreadyCommitted() {
        final MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/vigilis/view/")
                        .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                        .build());
        exchange.getResponse().setStatusCode(HttpStatus.OK);
        exchange.getResponse().setComplete().block();

        final RuntimeException ex = new RuntimeException("late");
        assertThatThrownBy(() -> handler.handle(exchange, ex).block())
                .isSameAs(ex);
    }
}
