package com.ids;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * IdsApplication — Spring Boot entry point for the AI Multi-Layer IDS Dashboard.
 *
 * Annotations explained:
 *
 * @SpringBootApplication combines three annotations:
 *   @Configuration       — this class can define Spring beans
 *   @EnableAutoConfiguration — auto-configures Tomcat, MVC, WebSocket based on classpath
 *   @ComponentScan       — scans com.ids.* for @Service, @RestController, @Component, etc.
 *
 * @EnableScheduling — activates @Scheduled methods (used in TrafficSimulator to
 *   broadcast one packet every 700ms to all connected dashboard clients).
 *
 * Startup sequence:
 *   1. Spring starts embedded Tomcat on port 8080
 *   2. WebSocketConfig registers STOMP endpoint at /ws
 *   3. Static files (index.html, style.css, app.js) served from /static/
 *   4. TrafficSimulator begins @Scheduled broadcasts automatically
 */
@SpringBootApplication
@EnableScheduling
public class IdsApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdsApplication.class, args);

        System.out.println();
        System.out.println("  ╔══════════════════════════════════════════════╗");
        System.out.println("  ║   AI-IDS Dashboard is running!               ║");
        System.out.println("  ║   Open browser: http://localhost:8080         ║");
        System.out.println("  ║   API health:   http://localhost:8080/api/health ║");
        System.out.println("  ╚══════════════════════════════════════════════╝");
        System.out.println();
    }
}
