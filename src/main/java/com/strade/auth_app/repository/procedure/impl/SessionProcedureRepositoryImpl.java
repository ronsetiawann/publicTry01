package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.procedure.SessionProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class SessionProcedureRepositoryImpl implements SessionProcedureRepository {

    private final DataSource dataSource;

    @Override
    public UUID storeRefreshOnLogin(
            UUID sessionId,
            byte[] refreshTokenHash,
            LocalDateTime refreshTokenExp
    ) {
        log.debug("Calling StoreRefreshOnLogin for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("StoreRefreshOnLogin")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("RefreshTokenHash", Types.VARBINARY),
                            new SqlParameter("RefreshTokenExp", Types.TIMESTAMP),
                            new SqlOutParameter("RefreshId", Types.VARCHAR)
                    );

            Map<String, Object> inParams = Map.of(
                    "SessionId", sessionId.toString(),
                    "RefreshTokenHash", refreshTokenHash,
                    "RefreshTokenExp", refreshTokenExp
            );

            Map<String, Object> result = jdbcCall.execute(inParams);

            String refreshIdStr = (String) result.get("RefreshId");
            return refreshIdStr != null ? UUID.fromString(refreshIdStr) : null;

        } catch (Exception e) {
            log.error("Error calling StoreRefreshOnLogin: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Store refresh token failed", e);
        }
    }
    @Override
    public UUID rotateRefreshToken(  //   Return RefreshId
                                     byte[] oldTokenHash,
                                     byte[] newTokenHash,
                                     LocalDateTime newExpiresAt
    ) {
        log.debug("Calling RotateRefreshToken");

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RotateRefreshToken")
                    .declareParameters(
                            new SqlParameter("OldTokenHash", Types.VARBINARY),
                            new SqlParameter("NewTokenHash", Types.VARBINARY),
                            new SqlParameter("NewExpiresAt", Types.TIMESTAMP),
                            new SqlOutParameter("SessionId", Types.VARCHAR),
                            new SqlOutParameter("RefreshId", Types.VARCHAR)
                    );

            Map<String, Object> result = jdbcCall.execute(
                    oldTokenHash,
                    newTokenHash,
                    Timestamp.valueOf(newExpiresAt)
            );

            //   Get OUTPUT parameters
            String sessionIdStr = (String) result.get("SessionId");
            String refreshIdStr = (String) result.get("RefreshId");

            UUID sessionId = sessionIdStr != null ? UUID.fromString(sessionIdStr) : null;
            UUID refreshId = refreshIdStr != null ? UUID.fromString(refreshIdStr) : null;

            log.info("  Refresh token rotated: sessionId={}, refreshId={}", sessionId, refreshId);

            return refreshId;

        } catch (Exception e) {
            log.error("❌ Error calling RotateRefreshToken: {}", e.getMessage(), e);

            // Check for token reuse
            if (e.getMessage() != null && e.getMessage().contains("REFRESH_REUSE_DETECTED")) {
                throw new AuthException(
                        ErrorCode.TOKEN_REUSE_DETECTED,
                        "Refresh token reuse detected - all tokens in family revoked",
                        e
                );
            }

            // Check for token not found
            if (e.getMessage() != null && e.getMessage().contains("REFRESH_TOKEN_NOT_FOUND")) {
                throw new AuthException(
                        ErrorCode.REFRESH_TOKEN_INVALID,
                        "Refresh token not found or expired",
                        e
                );
            }

            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Rotate refresh token failed",
                    e
            );
        }
    }

    @Override
    public void revokeSession(UUID sessionId, String reason) {
        log.debug("Calling RevokeSession for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RevokeSession")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("Reason", Types.NVARCHAR)
                    );

            jdbcCall.execute(sessionId.toString(), reason);

        } catch (Exception e) {
            log.error("Error calling RevokeSession: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Revoke session failed", e);
        }
    }

    @Override
    public void revokeAllSessionsForUser(
            String userId,
            UUID exceptSessionId,
            String reason
    ) {
        log.debug("Calling RevokeAllSessionsForUser for userId: {}", userId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("RevokeAllSessionsForUser")
                    .declareParameters(
                            new SqlParameter("UserId", Types.NVARCHAR),
                            new SqlParameter("ExceptSessionId", Types.VARCHAR),
                            new SqlParameter("Reason", Types.NVARCHAR)
                    );

            jdbcCall.execute(
                    userId,
                    exceptSessionId != null ? exceptSessionId.toString() : null,
                    reason
            );

        } catch (Exception e) {
            log.error("Error calling RevokeAllSessionsForUser: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Revoke all sessions failed", e);
        }
    }

    @Override
    public boolean verifyAccessClaims(UUID sessionId, String jti, String userId) {
        log.debug("Calling VerifyAccessClaims for sessionId: {}", sessionId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("VerifyAccessClaims")
                    .declareParameters(
                            new SqlParameter("SessionId", Types.VARCHAR),
                            new SqlParameter("Jti", Types.NVARCHAR),
                            new SqlParameter("UserId", Types.NVARCHAR)
                    );

            Map<String, Object> result = jdbcCall.execute(
                    sessionId.toString(),
                    jti,
                    userId
            );

            Object isValidObj = result.get("IsValid");
            if (isValidObj instanceof Boolean) {
                return (Boolean) isValidObj;
            } else if (isValidObj instanceof Number) {
                return ((Number) isValidObj).intValue() != 0;
            }
            return false;

        } catch (Exception e) {
            log.error("Error calling VerifyAccessClaims: {}", e.getMessage(), e);
            return false;
        }
    }

    @Override
    public void updateUserLogout(String userId, String terminalId) {
        log.debug("Calling updateUserLogOut for userId: {}, terminalId: {}", userId, terminalId);

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("dbo")
                    .withProcedureName("updateUserLogOut_v2")
                    .declareParameters(
                            new SqlParameter("userid", Types.NVARCHAR),
                            new SqlParameter("TerminalId", Types.NVARCHAR)
                    );

            Map<String, Object> inParams = new HashMap<>();
            inParams.put("userid", userId);
            inParams.put("TerminalId", terminalId != null ? terminalId : "UNKNOWN");

            jdbcCall.execute(inParams);

            log.debug("User logout recorded: userId={}, terminalId={}", userId, terminalId);

        } catch (Exception e) {
            log.error("Error calling updateUserLogOut: {}", e.getMessage(), e);
            throw new AuthException(ErrorCode.DATABASE_ERROR, "Update user logout failed", e);
        }
    }
}
