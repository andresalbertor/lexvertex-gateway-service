package com.lexvertex.gateway.error;

import com.lexvertex.gateway.constant.GatewayConstants;
import com.lexvertex.gateway.security.VigilisAuthenticationEntryPoint;
import org.apache.commons.lang3.Strings;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.boot.webflux.error.ErrorWebExceptionHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

/**
 * Sustituye la Whitelabel de Spring Boot por una página HTML estable del gateway
 * cuando el cliente es un navegador; las APIs reciben JSON sin detalle interno.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-11-14
 */
@Component
@Order(-2)
public class GatewayErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    private final String errorHtmlTemplate;

    /**
     * Carga la plantilla HTML de error desde el classpath.
     *
     * @param resourceLoader cargador de recursos de Spring
     */
    public GatewayErrorWebExceptionHandler(final ResourceLoader resourceLoader) {
        this.errorHtmlTemplate = loadTemplate(resourceLoader);
    }

    @Override
    public Mono<Void> handle(final ServerWebExchange exchange, final Throwable ex) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }

        final HttpStatus status = resolveStatus(ex);
        final ServerHttpRequest request = exchange.getRequest();
        if (shouldRenderHtml(request)) {
            return writeHtml(exchange.getResponse(), status);
        }
        return writeJson(exchange.getResponse(), status);
    }

    private static boolean shouldRenderHtml(final ServerHttpRequest request) {
        final String path = request.getURI().getRawPath();
        if (path != null && Strings.CS.startsWith(path, GatewayConstants.API_PREFIX)) {
            return false;
        }
        return VigilisAuthenticationEntryPoint.wantsHtml(request);
    }

    private Mono<Void> writeHtml(
            final ServerHttpResponse response,
            final HttpStatus status
    ) {
        final String body = errorHtmlTemplate
                .replace(GatewayConstants.ERROR_PLACEHOLDER_STATUS, String.valueOf(status.value()))
                .replace(GatewayConstants.ERROR_PLACEHOLDER_TITLE, htmlEscape(titleFor(status)))
                .replace(GatewayConstants.ERROR_PLACEHOLDER_MESSAGE, htmlEscape(messageFor(status)))
                .replace(GatewayConstants.ERROR_PLACEHOLDER_HOME_HREF, htmlEscape(GatewayConstants.PATH_HOME));

        response.setStatusCode(status);
        response.getHeaders().setContentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8));
        final var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private static Mono<Void> writeJson(final ServerHttpResponse response, final HttpStatus status) {
        final String body = "{\"status\":" + status.value()
                + ",\"error\":\"" + jsonEscape(status.getReasonPhrase())
                + "\",\"message\":\"" + jsonEscape(messageFor(status)) + "\"}";
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        final var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private static HttpStatus resolveStatus(final Throwable ex) {
        if (ex instanceof ResponseStatusException responseStatusException) {
            final HttpStatusCode code = responseStatusException.getStatusCode();
            final HttpStatus resolved = HttpStatus.resolve(code.value());
            return resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR;
        }
        if (hasCause(ex, ConnectException.class)) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }
        if (hasCause(ex, TimeoutException.class)) {
            return HttpStatus.GATEWAY_TIMEOUT;
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private static boolean hasCause(final Throwable ex, final Class<? extends Throwable> type) {
        Throwable current = ex;
        while (current != null) {
            if (type.isInstance(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static String titleFor(final HttpStatus status) {
        return switch (status) {
            case NOT_FOUND -> "No encontrado";
            case BAD_GATEWAY, SERVICE_UNAVAILABLE -> "Servicio no disponible";
            case GATEWAY_TIMEOUT -> "Tiempo de espera agotado";
            default -> "Error inesperado";
        };
    }

    private static String messageFor(final HttpStatus status) {
        return switch (status) {
            case NOT_FOUND -> "La página solicitada no existe o ya no está disponible.";
            case BAD_GATEWAY, SERVICE_UNAVAILABLE ->
                    "El servicio no está disponible en este momento. Intente de nuevo en unos minutos.";
            case GATEWAY_TIMEOUT ->
                    "El servicio tardó demasiado en responder. Intente de nuevo en unos minutos.";
            default -> "Ocurrió un error al procesar la solicitud. Intente de nuevo más tarde.";
        };
    }

    private static String loadTemplate(final ResourceLoader resourceLoader) {
        final Resource resource = resourceLoader.getResource(GatewayConstants.ERROR_HTML_CLASSPATH);
        try (InputStream inputStream = resource.getInputStream()) {
            return StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException("No se pudo cargar la plantilla de error del gateway", ex);
        }
    }

    private static String htmlEscape(final String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String jsonEscape(final String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
