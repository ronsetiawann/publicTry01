package com.strade.auth_app.service;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing temporary TOTP setup tokens using Redis

 * Redis keys structure:
 * - totp:setup:{tokenId} → TotpSetupData (TTL: 10 minutes)
 * - totp:access:{tokenId} → AccessInfo (for audit, TTL: 1 hour)

 * Benefits:
 * - No database table needed
 * - Auto-expiry with Redis TTL
 * - Fast access
 * - Perfect for temporary data
 * - Single-use enforcement with delete
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TotpTokenService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String TOKEN_PREFIX = "totp:setup:";
    private static final String ACCESS_PREFIX = "totp:access:";
    private static final int TOKEN_EXPIRY_MINUTES = 10;
    private static final int ACCESS_LOG_EXPIRY_HOURS = 1;

    /**
     * Create temporary token for TOTP setup data
     * Token expires in 10 minutes and stored in Redis
     *
     * @param userId User identifier
     * @param secret TOTP secret key
     * @param qrCodeUri QR code URI for authenticator apps
     * @param backupCodes List of backup codes
     * @return Token UUID
     */
    public UUID createToken(
            String userId,
            String secret,
            String qrCodeUri,
            List<String> backupCodes
    ) {
        UUID tokenId = UUID.randomUUID();
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(TOKEN_EXPIRY_MINUTES);

        TotpSetupData data = TotpSetupData.builder()
                .userId(userId)
                .secret(secret)
                .qrCodeUri(qrCodeUri)
                .backupCodes(backupCodes)
                .createdAt(now)
                .expiresAt(expiresAt)
                .build();

        String key = TOKEN_PREFIX + tokenId.toString();

        // Save to Redis with TTL
        redisTemplate.opsForValue().set(
                key,
                data,
                TOKEN_EXPIRY_MINUTES,
                TimeUnit.MINUTES
        );

        log.info("Created TOTP setup token {} for user {} in Redis (expires at {})",
                tokenId, userId, expiresAt);

        return tokenId;
    }

    /**
     * Retrieve and consume token (single-use)
     * Token is deleted after retrieval to enforce single-use
     *
     * @param tokenId Token UUID
     * @param ipAddress Client IP address for audit
     * @return TOTP setup data
     * @throws AuthException if token invalid, expired, or already used
     */
    public TotpSetupData retrieveAndConsume(UUID tokenId, String ipAddress) {
        String key = TOKEN_PREFIX + tokenId.toString();

        // Get first (Redis 5.0 compatible)
        TotpSetupData data = (TotpSetupData) redisTemplate.opsForValue().get(key);

        if (data == null) {
            log.warn("Invalid or expired TOTP setup token: {} from IP: {}", tokenId, ipAddress);
            throw new AuthException(
                    ErrorCode.INVALID_TOKEN,
                    "Invalid, expired, or already used token"
            );
        }

        // Delete after successful get
        redisTemplate.delete(key);

        log.info("TOTP setup token {} accessed by user {} from IP {}",
                tokenId, data.getUserId(), ipAddress);

        storeAccessInfo(tokenId, data.getUserId(), ipAddress);

        return data;
    }

    /**
     * Check if token exists and is valid
     * Does NOT consume the token
     *
     * @param tokenId Token UUID
     * @return true if token exists and not expired
     */
    public boolean isTokenValid(UUID tokenId) {
        String key = TOKEN_PREFIX + tokenId.toString();
        Boolean exists = redisTemplate.hasKey(key);
        return exists != null && exists;
    }

    /**
     * Get token TTL (Time To Live)
     *
     * @param tokenId Token UUID
     * @return Remaining seconds, or -1 if token doesn't exist
     */
    public long getTokenTTL(UUID tokenId) {
        String key = TOKEN_PREFIX + tokenId.toString();
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
        return ttl != null ? ttl : -1;
    }

    /**
     * Manually revoke/delete a token
     * Useful if user requests cancellation
     *
     * @param tokenId Token UUID
     * @return true if token was deleted
     */
    public boolean revokeToken(UUID tokenId) {
        String key = TOKEN_PREFIX + tokenId.toString();
        Boolean deleted = redisTemplate.delete(key);

        if (Boolean.TRUE.equals(deleted)) {
            log.info("Manually revoked TOTP setup token {}", tokenId);
            return true;
        }

        return false;
    }

    /**
     * Store access information for audit purposes
     * This is kept separate from the main token data
     * Expires after 1 hour
     *
     * @param tokenId Token UUID
     * @param userId User identifier
     * @param ipAddress Client IP address
     */
    private void storeAccessInfo(UUID tokenId, String userId, String ipAddress) {
        try {
            String accessKey = ACCESS_PREFIX + tokenId.toString();

            AccessInfo accessInfo = AccessInfo.builder()
                    .tokenId(tokenId.toString())
                    .userId(userId)
                    .ipAddress(ipAddress)
                    .accessedAt(LocalDateTime.now())
                    .build();

            redisTemplate.opsForValue().set(
                    accessKey,
                    accessInfo,
                    ACCESS_LOG_EXPIRY_HOURS,
                    TimeUnit.HOURS
            );

            log.debug("Stored access info for token {} in Redis", tokenId);
        } catch (Exception e) {
            // Don't fail the main operation if audit logging fails
            log.error("Failed to store access info for token {}", tokenId, e);
        }
    }

    /**
     * Get access information for a token (for audit/monitoring)
     *
     * @param tokenId Token UUID
     * @return Access information if available
     */
    public AccessInfo getAccessInfo(UUID tokenId) {
        String accessKey = ACCESS_PREFIX + tokenId.toString();
        return (AccessInfo) redisTemplate.opsForValue().get(accessKey);
    }

    /**
     * Get statistics about TOTP tokens in Redis
     * Useful for monitoring
     *
     * @return Token statistics
     */
    public TokenStats getTokenStats() {
        try {
            // Count active tokens
            var tokenKeys = redisTemplate.keys(TOKEN_PREFIX + "*");
            int activeTokens = tokenKeys.size();

            // Count access logs
            var accessKeys = redisTemplate.keys(ACCESS_PREFIX + "*");
            int accessLogs = accessKeys.size();

            return TokenStats.builder()
                    .activeTokens(activeTokens)
                    .accessLogs(accessLogs)
                    .build();
        } catch (Exception e) {
            log.error("Failed to get token statistics", e);
            return TokenStats.builder().build();
        }
    }

    //========================================
    // DTOs
    //========================================

    /**
     * DTO for TOTP setup data stored in Redis
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TotpSetupData implements Serializable {

        private static final long serialVersionUID = 1L;

        private String userId;
        private String secret;
        private String qrCodeUri;
        private List<String> backupCodes;
        private LocalDateTime createdAt;
        private LocalDateTime expiresAt;
    }

    /**
     * DTO for access audit information
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AccessInfo {
        private String tokenId;
        private String userId;
        private String ipAddress;
        private LocalDateTime accessedAt;
    }

    /**
     * DTO for token statistics
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class TokenStats {
        private int activeTokens;
        private int accessLogs;
    }
}