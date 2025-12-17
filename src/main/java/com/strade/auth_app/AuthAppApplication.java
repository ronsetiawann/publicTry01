package com.strade.auth_app;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.TimeZone;

@SpringBootApplication
@EnableConfigurationProperties
@EnableCaching
@EnableAsync
@EnableScheduling
@EnableJpaAuditing
public class AuthAppApplication {

	/**
	 * Set default timezone JVM → Asia/Jakarta
	 * Berlaku untuk:
	 * - LocalDateTime.now()
	 * - ZonedDateTime.now()
	 * - Auditing @CreatedDate / @LastModifiedDate
	 * - Logging
	 * - Hibernate timestamps
	 */
	@PostConstruct
	public void init() {
		TimeZone.setDefault(TimeZone.getTimeZone("Asia/Jakarta"));
		System.out.println(">>> Default TimeZone set to Asia/Jakarta");
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthAppApplication.class, args);
	}
}
