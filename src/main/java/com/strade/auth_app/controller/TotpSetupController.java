package com.strade.auth_app.controller;

import com.strade.auth_app.service.TotpTokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Controller for TOTP setup token access
 * Token data is stored in Redis with auto-expiry (10 minutes)
 *
 * Endpoints:
 * - GET /api/auth/totp/setup/{token} - Retrieve and consume token (single-use)
 * - GET /api/auth/totp/setup/{token}/validate - Check token validity
 * - GET /api/auth/totp/setup/stats - Get token statistics
 */
@RestController
@RequestMapping("/api/auth/totp/setup")
@Slf4j
@RequiredArgsConstructor
public class TotpSetupController {

    private final TotpTokenService totpTokenService;

    /**
     * Retrieve TOTP setup data using temporary token
     *
     * Token can only be used ONCE and expires after 10 minutes.
     * After retrieval, token is automatically deleted from Redis.
     *
     * @param token The temporary access token from email (UUID format)
     * @param request HTTP request to extract IP address
     * @return TOTP setup data (secret, QR URI, backup codes)
     */
    @GetMapping("/{token}")
    public ResponseEntity<?> getTotpSetupData(
            @PathVariable String token,
            HttpServletRequest request
    ) {
        try {
            // Parse token as UUID
            UUID tokenId = UUID.fromString(token);
            String ipAddress = getClientIp(request);

            log.info("TOTP setup token access attempt: {} from IP: {}", tokenId, ipAddress);

            // Retrieve and consume token (will be deleted from Redis)
            TotpTokenService.TotpSetupData setupData = totpTokenService.retrieveAndConsume(
                    tokenId,
                    ipAddress
            );

            log.info("TOTP setup token {} successfully retrieved by user {}", tokenId, setupData.getUserId());

            return ResponseEntity.ok(setupData);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid token format: {}", token);
            return ResponseEntity.badRequest().body(new ErrorResponse(
                    "INVALID_TOKEN",
                    "Invalid token format. Token must be a valid UUID."
            ));
        } catch (Exception e) {
            log.error("Error retrieving TOTP setup data for token: {}", token, e);
            return ResponseEntity.badRequest().body(new ErrorResponse(
                    "TOKEN_ERROR",
                    e.getMessage()
            ));
        }
    }

    /**
     * Validate token without consuming it
     *
     * Useful for frontend to check token validity before displaying page.
     * Does NOT delete the token from Redis.
     *
     * @param token The temporary access token
     * @return Token validation response with TTL
     */
    @GetMapping("/{token}/validate")
    public ResponseEntity<?> validateToken(@PathVariable String token) {
        try {
            UUID tokenId = UUID.fromString(token);

            boolean isValid = totpTokenService.isTokenValid(tokenId);
            long ttlSeconds = totpTokenService.getTokenTTL(tokenId);

            String message;
            if (ttlSeconds > 0) {
                long minutes = ttlSeconds / 60;
                long seconds = ttlSeconds % 60;
                message = String.format("Token expires in %d minutes %d seconds", minutes, seconds);
            } else if (ttlSeconds == -1) {
                message = "Token exists but has no expiration";
            } else {
                message = "Token expired or does not exist";
            }

            log.debug("Token validation: {} - Valid: {}, TTL: {} seconds", tokenId, isValid, ttlSeconds);

            return ResponseEntity.ok(new TokenValidationResponse(
                    isValid,
                    ttlSeconds,
                    message
            ));

        } catch (IllegalArgumentException e) {
            log.warn("Invalid token format for validation: {}", token);
            return ResponseEntity.badRequest().body(new ErrorResponse(
                    "INVALID_TOKEN",
                    "Invalid token format"
            ));
        } catch (Exception e) {
            log.error("Error validating token: {}", token, e);
            return ResponseEntity.internalServerError().body(new ErrorResponse(
                    "VALIDATION_ERROR",
                    "Failed to validate token"
            ));
        }
    }

    /**
     * Get token statistics (for monitoring/admin)
     *
     * Returns count of active tokens and access logs in Redis.
     * Can be protected with admin role if needed.
     *
     * @return Token statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getTokenStats() {
        try {
            TotpTokenService.TokenStats stats = totpTokenService.getTokenStats();

            log.debug("Token statistics requested - Active: {}, Access logs: {}",
                    stats.getActiveTokens(), stats.getAccessLogs());

            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("Error getting token statistics", e);
            return ResponseEntity.internalServerError().body(new ErrorResponse(
                    "STATS_ERROR",
                    "Failed to retrieve statistics"
            ));
        }
    }

    /**
     * Get client IP address from request
     * Handles proxied requests (X-Forwarded-For, X-Real-IP headers)
     *
     * @param request HTTP request
     * @return Client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        // Check X-Forwarded-For header (for load balancers/proxies)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, take the first one
            return xForwardedFor.split(",")[0].trim();
        }

        // Check X-Real-IP header (nginx proxy)
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        // Fallback to remote address
        return request.getRemoteAddr();
    }

    //========================================
    // Response DTOs
    //========================================

    /**
     * Error response DTO
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class ErrorResponse {
        private String code;
        private String message;
    }

    /**
     * Token validation response DTO
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class TokenValidationResponse {
        private boolean valid;
        private long ttlSeconds;
        private String message;
    }
}