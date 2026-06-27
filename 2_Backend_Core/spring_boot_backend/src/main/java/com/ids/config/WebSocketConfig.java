package com.ids.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * WebSocketConfig — configures the STOMP WebSocket message broker.
 *
 * What is STOMP?
 *   STOMP (Simple Text Oriented Messaging Protocol) is a lightweight
 *   publish/subscribe messaging protocol that runs over WebSocket.
 *   It lets the server push messages to the browser without the browser
 *   having to ask repeatedly (no HTTP polling needed).
 *
 * Message flow in this project:
 *   Browser opens  → ws://localhost:8080/ws  (SockJS WebSocket)
 *   Browser runs   → stompClient.subscribe('/topic/packets', handler)
 *   Server runs    → messagingTemplate.convertAndSend("/topic/packets", packet)
 *   Browser gets   → handler(message) fires automatically with new packet data
 *
 * What is SockJS?
 *   SockJS is a JavaScript library that tries to use native WebSocket first,
 *   and falls back to HTTP long-polling if WebSocket is blocked.
 *   Enabling withSockJS() on the server lets the SockJS client connect.
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    /**
     * Register the WebSocket endpoint that browser clients connect to.
     *
     * URL: ws://localhost:8080/ws
     * SockJS URL: http://localhost:8080/ws/info (auto-used by SockJS client)
     *
     * setAllowedOriginPatterns("*") — allow connections from any origin
     * (needed when testing from a browser on the same machine)
     */
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*")
                .withSockJS();
    }

    /**
     * Configure the in-memory STOMP message broker channels.
     *
     * enableSimpleBroker("/topic") — creates an in-memory broker for /topic/* channels.
     *   The TrafficSimulator publishes to /topic/packets and /topic/devices.
     *   All browser clients subscribed to these topics receive the messages.
     *
     * setApplicationDestinationPrefixes("/app") — prefix for client→server messages
     *   (not used in this project — server only pushes, never receives from browser).
     */
    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");         // server → all subscribed clients
        registry.setApplicationDestinationPrefixes("/app"); // client → server (unused here)
    }
}
