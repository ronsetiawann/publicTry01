package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * IDX WhatsApp Business API Configuration
 * Provider: Indonesia Stock Exchange (IDX)
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "whatsapp.idx")
public class IDXWhatsAppProperties {

    /**
     * Bearer token for API authentication
     */
    private String bearerToken;

    /**
     * Base URL for IDX WhatsApp API
     */
    private String baseUrl = "https://dev-hub.idxsti.co.id/api/v1/ext/";

    /**
     * Template configuration
     */
    private TemplateConfig template = new TemplateConfig();

    @Getter
    @Setter
    public static class TemplateConfig {
        /**
         * OTP template ID (must be pre-created and approved)
         */
        private String otpTemplateId;

        /**
         * Template language code (e.g., en_US, id_ID)
         */
        private String languageCode = "id_ID";

        /**
         * Template category for OTP
         */
        private String otpCategory = "AUTHENTICATION";
    }
}