package com.strade.auth_app.config.properties;

import com.strade.auth_app.util.PasswordEncryptionUtil;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Main application properties
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private String name = "STRADE Auth Service";
    private String version = "1.0.0";

    private JwtProperties jwt = new JwtProperties();
    private SecurityProperties security = new SecurityProperties();
    private PasswordProperties password = new PasswordProperties();
    private FrontendEncryption frontendEncryption = new FrontendEncryption();

    /**
     * Password encryption configuration (MERGED & CLEANED)
     */
    @Data
    public static class PasswordProperties {
        private String ledgerHashPassword = "true";
        private PasswordEncryptionUtil.DecryptMode frontendDecryptMode = PasswordEncryptionUtil.DecryptMode.WEB;
        private HashStrategy hashStrategy = HashStrategy.ENDPOINT;
        private String hashEndpointUrl = "https://s-trade.co.id/Home/SHash";

        public enum HashStrategy {
            JNA, ENDPOINT, AUTO
        }

        // Helper methods
        public boolean isEncryptionEnabled() {
            return "true".equalsIgnoreCase(ledgerHashPassword) ||
                    "simple".equalsIgnoreCase(ledgerHashPassword);
        }

        public boolean isHashMode() {
            return "true".equalsIgnoreCase(ledgerHashPassword);
        }

        public boolean isSimpleMode() {
            return "simple".equalsIgnoreCase(ledgerHashPassword);
        }
    }

    @Data
    public static class FrontendEncryption {
        private boolean enabled = false;
        private String key;
        private String iv;

        /**
         * Check if frontend encryption is properly configured
         */
        public boolean isConfigured() {
            return enabled && key != null && !key.isEmpty() && iv != null && !iv.isEmpty();
        }
    }

}