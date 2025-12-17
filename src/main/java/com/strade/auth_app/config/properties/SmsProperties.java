package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * SMS configuration properties
 * Support multiple providers: Twilio, Infobip, Zenziva, etc.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "sms")
public class SmsProperties {

    private String provider = "twilio"; // test provider

    // Twilio Configuration
    private TwilioConfig twilio = new TwilioConfig();

    @Getter
    @Setter
    public static class TwilioConfig {
        private String accountSid;
        private String authToken;
        private String fromNumber;
        private String baseUrl = "https://api.twilio.com/2010-04-01";
    }
}