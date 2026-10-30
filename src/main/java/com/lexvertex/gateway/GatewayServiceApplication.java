package com.lexvertex.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Puerta de enlace API Gateway del sistema con enrutamiento reactivo y validación de seguridad.
 *
 * @author andres.restrepo@alternova.com
 * @version 1.0.0
 * @since 2026-04-20
 */
@SpringBootApplication
public class GatewayServiceApplication {

    /**
     * Punto de entrada principal para iniciar el microservicio reactivo de API Gateway.
     *
     * @param args argumentos de línea de comandos
     */
    public static void main(final String[] args) {
        SpringApplication.run(GatewayServiceApplication.class, args);
    }
}
