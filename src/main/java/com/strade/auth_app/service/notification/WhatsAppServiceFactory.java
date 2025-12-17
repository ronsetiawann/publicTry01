package com.strade.auth_app.service.notification;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

/**
 * WhatsApp Service Factory
 *
 * Factory pattern to dynamically select WhatsApp provider based on configuration
 * Supports multiple providers: Mekari, IDX, and future providers
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class WhatsAppServiceFactory {

    private final ApplicationContext applicationContext;

    @Value("${whatsapp.provider:mekari}")
    private String whatsappProvider;

    /**
     * Get the configured WhatsApp service implementation
     *
     * @return WhatsAppService instance based on configuration
     * @throws IllegalArgumentException if provider is not supported
     */
    public WhatsAppService getWhatsAppService() {
        log.debug("Getting WhatsApp service for provider: {}", whatsappProvider);

        return switch (whatsappProvider.toLowerCase()) {
            case "mekari" -> {
                log.info("Using Mekari WhatsApp provider");
                yield applicationContext.getBean(MekariWhatsAppService.class);
            }
            case "idx" -> {
                log.info("Using IDX WhatsApp provider");
                yield applicationContext.getBean(IDXWhatsAppService.class);
            }
            default -> {
                log.error("Unknown WhatsApp provider: {}", whatsappProvider);
                throw new IllegalArgumentException(
                        "Unknown WhatsApp provider: " + whatsappProvider +
                                ". Supported providers: mekari, idx"
                );
            }
        };
    }

    /**
     * Get current provider name
     *
     * @return Provider name (mekari, idx, etc.)
     */
    public String getCurrentProvider() {
        return whatsappProvider;
    }

    /**
     * Check if a specific provider is active
     *
     * @param providerName Provider name to check
     * @return true if the provider is active
     */
    public boolean isProviderActive(String providerName) {
        return whatsappProvider.equalsIgnoreCase(providerName);
    }
}