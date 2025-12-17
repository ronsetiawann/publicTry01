package com.strade.auth_app.repository.procedure.impl;

import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.procedure.CleanupProcedureRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;

/**
 * Repository implementation for maintenance stored procedures
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class CleanupProcedureRepositoryImpl implements CleanupProcedureRepository {

    private final DataSource dataSource;

    @Override
    public void cleanupExpiredTokens() {
        log.info("Calling Auth.CleanupExpiredTokens");

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("CleanupExpiredTokens");

            jdbcCall.execute();

            log.info("✅ CleanupExpiredTokens executed successfully");

        } catch (Exception e) {
            log.error("❌ Error calling CleanupExpiredTokens: {}", e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Cleanup expired tokens failed",
                    e
            );
        }
    }

    @Override
    public void securityMonitor() {
        log.info("Calling Auth.SecurityMonitor");

        try {
            SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource)
                    .withSchemaName("Auth")
                    .withProcedureName("SecurityMonitor");

            jdbcCall.execute();

            log.info("✅ SecurityMonitor executed successfully");

        } catch (Exception e) {
            log.error("❌ Error calling SecurityMonitor: {}", e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Security monitor job failed",
                    e
            );
        }
    }
}
