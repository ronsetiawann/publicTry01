package com.strade.auth_app.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Controller for serving TOTP setup HTML page
 *
 * Returns HTML directly to avoid circular view path error
 * This ensures the page can be accessed without authentication
 *
 * URL Pattern: /totp-setup/{token}
 * Example: http://localhost:8098/totp-setup/5bd70ccc-01ce-4dfe-ba15-558f2627917c
 */
@RestController
@Slf4j
public class TotpSetupViewController {

    /**
     * Serve TOTP setup HTML page
     *
     * Returns HTML content directly (not through view resolver)
     *
     * @param token UUID token from email link
     * @return HTML page as ResponseEntity
     */
    @GetMapping(value = "/totp-setup/{token}", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> showTotpSetupPage(@PathVariable String token) {
        log.info("Serving TOTP setup page for token: {}", token);

        try {
            // Read HTML file from classpath (static folder)
            ClassPathResource resource = new ClassPathResource("static/totp-setup.html");

            if (!resource.exists()) {
                log.error("TOTP setup HTML file not found at: static/totp-setup.html");
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .contentType(MediaType.TEXT_HTML)
                        .body(buildErrorHtml("File not found", "TOTP setup page is not available."));
            }

            // Read file content
            try (InputStream inputStream = resource.getInputStream()) {
                String html = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);

                // Set headers
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.TEXT_HTML);
                headers.setCacheControl("no-cache, no-store, must-revalidate");
                headers.setPragma("no-cache");
                headers.setExpires(0);

                log.info("TOTP setup page served successfully for token: {}", token);

                return new ResponseEntity<>(html, headers, HttpStatus.OK);
            }

        } catch (IOException e) {
            log.error("Failed to read TOTP setup HTML file", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.TEXT_HTML)
                    .body(buildErrorHtml("Server Error", "Failed to load TOTP setup page. Please try again later."));
        }
    }

    /**
     * Build error HTML page
     */
    private String buildErrorHtml(String title, String message) {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s - STRADE</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        padding: 20px;
                    }
                    .container {
                        background: white;
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                        max-width: 500px;
                        width: 100%%;
                        padding: 40px;
                        text-align: center;
                    }
                    h1 {
                        color: #c33;
                        font-size: 28px;
                        margin-bottom: 20px;
                    }
                    p {
                        color: #666;
                        font-size: 16px;
                        line-height: 1.6;
                        margin-bottom: 20px;
                    }
                    .button {
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white;
                        padding: 12px 30px;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        cursor: pointer;
                        text-decoration: none;
                        display: inline-block;
                        margin-top: 10px;
                    }
                    .button:hover { opacity: 0.9; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ %s</h1>
                    <p>%s</p>
                    <p style="font-size: 14px; color: #999;">If this problem persists, please contact support.</p>
                    <a href="javascript:history.back()" class="button">← Go Back</a>
                </div>
            </body>
            </html>
            """.formatted(title, title, message);
    }
}