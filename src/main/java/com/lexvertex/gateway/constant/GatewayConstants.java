package com.lexvertex.gateway.constant;

import java.util.List;

/**
 * Constantes centralizadas para el API Gateway reactivo del sistema.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
public final class GatewayConstants {

    /**
     * Constructor privado para evitar la instanciación de la clase de constantes.
     */
    private GatewayConstants() {
        // Evita instanciación
    }

    // =========================================================================
    // Cabeceras HTTP y delimitadores
    // =========================================================================

    /** Nombre de la cabecera HTTP inyectada downstream con los permisos efectivos del usuario. */
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";

    /** Cabecera HTTP inyectada downstream con los códigos de rol del JWT. */
    public static final String HEADER_USER_ROLES = "X-User-Roles";

    /** Cabecera estándar de autorización HTTP. */
    public static final String HEADER_AUTHORIZATION = "Authorization";

    /** Cabecera estándar de tipo de contenido HTTP. */
    public static final String HEADER_CONTENT_TYPE = "Content-Type";

    /** Cabecera de clave de idempotencia HTTP. */
    public static final String HEADER_IDEMPOTENCY_KEY = "Idempotency-Key";

    /** Cabecera de identificador de correlación de trazabilidad. */
    public static final String HEADER_CORRELATION_ID = "X-Correlation-Id";

    /** Delimitador coma para concatenar listas en cabeceras HTTP. */
    public static final String DELIMITER_COMMA = ",";

    // =========================================================================
    // Claims JWT y prefijos de autoridades
    // =========================================================================

    /** Nombre del claim del token JWT que contiene los códigos de rol. */
    public static final String CLAIM_ROLES = "roles";

    /** Nombre del claim del token JWT que contiene los permisos explícitos. */
    public static final String CLAIM_PERMISSIONS = "permissions";

    /** Nombre del claim del token JWT que indica cambio obligatorio de contraseña. */
    public static final String CLAIM_MUST_CHANGE_PASSWORD = "mustChangePassword";

    /** Prefijo estándar de Spring Security para autoridades basadas en rol. */
    public static final String ROLE_PREFIX = "ROLE_";

    // =========================================================================
    // Caché reactiva y consultas R2DBC
    // =========================================================================

    /** Nombre de la región de caché reactiva para permisos por rol. */
    public static final String CACHE_ROLE_PERMISSIONS = "rolePermissions";

    /** Expresión SpEL de clave para la caché de permisos por lista de roles. */
    public static final String CACHE_KEY_ROLES = "#roles";

    /** Tiempo de expiración en minutos para las entradas de la caché local. */
    public static final long CACHE_EXPIRE_MINUTES = 10L;

    /** Tamaño máximo de entradas permitidas en la caché local Caffeine. */
    public static final long CACHE_MAX_SIZE = 100L;

    /** Nombre del parámetro enlazado para la lista de códigos de rol en consultas R2DBC. */
    public static final String PARAM_ROLES = "roles";

    /** Nombre de la columna que almacena el código del permiso en base de datos. */
    public static final String COL_CODE = "code";

    // =========================================================================
    // Rutas de seguridad y políticas CORS
    // =========================================================================

    /** Patrón comodín global para rutas HTTP y registro CORS. */
    public static final String PATH_ALL = "/**";

    /** Ruta de cambio de contraseña autenticada permitida durante cambio forzoso. */
    public static final String PATH_AUTH_PASSWORD_CHANGE = "/api/v1/auth/password/change";

    /** Ruta de cierre de sesión público y permitido durante cambio forzoso. */
    public static final String PATH_AUTH_LOGOUT = "/api/v1/auth/logout";

    /** Ruta de renovación de token permitida durante cambio forzoso. */
    public static final String PATH_AUTH_REFRESH = "/api/v1/auth/refresh";

    /** Arreglo inmutable de patrones de rutas públicas sin requerimiento de JWT en el Gateway. */
    public static final String[] PUBLIC_PATHS = {
            "/api/v1/auth/login",
            PATH_AUTH_REFRESH,
            PATH_AUTH_LOGOUT,
            "/api/v1/auth/mfa/totp/setup",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/mfa/email-code",
            "/api/v1/auth/mfa/email-code/verify",
            "/api/v1/auth/password/forgot",
            "/api/v1/auth/password/reset",
            "/api/v1/auth/password/security-challenge",
            "/api/v1/auth/password/security-reset",
            "/api/v1/auth/password/recovery-options",
            "/api/v1/auth/invitations/**",
            "/api/v1/auth/email/**",
            "/.well-known/**",
            "/actuator/health",
            "/actuator/info",
            // Vigilís (público temporal: UI, estáticos, Swagger y health)
            "/view",
            "/view/**",
            "/static/**",
            "/docs",
            "/docs/**",
            "/redoc",
            "/redoc/**",
            "/openapi.json",
            "/api/v1/health"
    };

    /**
     * Prefijo de la API Lexvertex versionada.
     */
    public static final String LEXVERTEX_API_V1_PREFIX = "/api/v1/";

    /** Prefijo genérico de APIs HTTP bajo el Gateway. */
    public static final String API_PREFIX = "/api/";

    /** Hostname público de Vigilís (sin puerto). */
    public static final String VIGILIS_HOST = "vigilis.lexvertex.cloud";

    /** Cabecera Host HTTP. */
    public static final String HEADER_HOST = "Host";

    /** Valor por defecto de orígenes CORS (prod www/apex + frontend local + Vigilís). */
    public static final String CORS_DEFAULT_ORIGINS =
            "https://www.lexvertex.cloud,https://lexvertex.cloud,https://vigilis.lexvertex.cloud,"
                    + "http://localhost:8089,http://127.0.0.1:8089";

    /** Lista inmutable de métodos HTTP permitidos en políticas CORS. */
    public static final List<String> CORS_ALLOWED_METHODS = List.of(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
    );

    /** Lista inmutable de cabeceras HTTP permitidas en políticas CORS. */
    public static final List<String> CORS_ALLOWED_HEADERS = List.of(
            HEADER_AUTHORIZATION,
            HEADER_CONTENT_TYPE,
            HEADER_IDEMPOTENCY_KEY,
            HEADER_CORRELATION_ID
    );

    /** Tiempo máximo en segundos para cachear respuestas preflight CORS. */
    public static final long CORS_MAX_AGE_SECONDS = 3600L;
}
