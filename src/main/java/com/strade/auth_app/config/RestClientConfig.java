package com.strade.auth_app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Configuration class for setting up RestTemplate bean with timeout.
 */
@Configuration
public class RestClientConfig {

    @Bean
    public RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();

        // Set connection timeout (10 seconds)
        factory.setConnectTimeout(10000);

        // Set read timeout (30 seconds)
        factory.setReadTimeout(30000);

        return new RestTemplate(factory);
    }
}