package com.strade.auth_app.repository.procedure;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Repository for session-related stored procedures
 */
public interface SessionProcedureRepository {

    /**
     * Store refresh token on login
     *
     * @param sessionId Session ID
     * @param refreshTokenHash Hashed refresh token
     * @param refreshTokenExp Expiration time
     * @return Refresh token ID
     */
    UUID storeRefreshOnLogin(
            UUID sessionId,
            byte[] refreshTokenHash,
            java.time.LocalDateTime refreshTokenExp
    );

    /**
     * Rotate refresh token with reuse detection
     *
     * @param oldTokenHash Old token hash
     * @param newTokenHash New token hash
     * @param newExpiresAt New expiration time
     * @return New refresh token ID
     * @throws RuntimeException if token reuse detected
     */
    UUID rotateRefreshToken(
            byte[] oldTokenHash,
            byte[] newTokenHash,
            LocalDateTime newExpiresAt
    );

    /**
     * Revoke a single session
     */
    void revokeSession(UUID sessionId, String reason);

    /**
     * Revoke all sessions for a user
     */
    void revokeAllSessionsForUser(
            String userId,
            UUID exceptSessionId,
            String reason
    );

    void updateUserLogout(String userId, String terminalId);

    /**
     * Verify access token claims
     *
     * @return true if valid, false otherwise
     */
    boolean verifyAccessClaims(
            UUID sessionId,
            String jti,
            String userId
    );
}
