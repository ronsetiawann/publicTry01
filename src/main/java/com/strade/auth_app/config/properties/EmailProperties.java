package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Email configuration properties
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.mail")
public class EmailProperties {

    private String host;
    private Integer port;
    private String username;
    private String password;
    private String from;
    private String fromName;

    private String defaultEncoding;
    private boolean testConnection;
    private boolean enabled;

    private Smtp smtp = new Smtp();
    private TotpEmailConfig totp = new TotpEmailConfig();

    @Getter
    @Setter
    public static class Smtp {
        private boolean auth;
        private boolean starttlsEnable;
        private boolean starttlsRequired;
        private Integer connectionTimeout;
        private Integer timeout;
        private Integer writeTimeout;
    }

    @Setter
    @Getter
    public static class TotpEmailConfig {
        private String deliveryMode;
        private String setupBaseUrl;
        private int tokenExpiryMinutes;
    }
}