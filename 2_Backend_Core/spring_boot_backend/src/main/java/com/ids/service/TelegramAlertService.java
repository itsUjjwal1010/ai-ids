package com.ids.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
public class TelegramAlertService {

    private static final Logger log = LoggerFactory.getLogger(TelegramAlertService.class);
    private static final String TELEGRAM_API_URL = "https://api.telegram.org/bot%s/sendMessage";

    @Value("${telegram.bot.token}")
    private String botToken;

    @Value("${telegram.chat.id}")
    private String chatId;

    private final HttpClient httpClient;

    public TelegramAlertService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public void sendAlert(String message) {
        if (botToken == null || botToken.isEmpty() || chatId == null || chatId.isEmpty()) {
            log.warn("Telegram bot token or chat ID is not configured.");
            return;
        }

        try {
            String url = String.format(TELEGRAM_API_URL, botToken);
            String payload = "chat_id=" + chatId + "&text=" + URLEncoder.encode(message, StandardCharsets.UTF_8) + "&parse_mode=Markdown";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(response -> {
                        if (response.statusCode() != 200) {
                            log.error("Failed to send Telegram alert. Status: {}, Body: {}", response.statusCode(), response.body());
                        } else {
                            log.info("Telegram alert sent successfully.");
                        }
                    })
                    .exceptionally(e -> {
                        log.error("Error sending Telegram alert: {}", e.getMessage());
                        return null;
                    });

        } catch (Exception e) {
            log.error("Exception occurred while building Telegram request: {}", e.getMessage());
        }
    }
}
