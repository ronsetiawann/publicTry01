package com.strade.auth_app.security.jwt;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.entity.KeyStore;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.exception.TokenException;
import com.strade.auth_app.repository.jpa.KeyStoreRepository;
import com.strade.auth_app.repository.jpa.UserViewRepository;
import com.strade.auth_app.util.DateTimeUtil;
import com.strade.auth_app.util.RoleUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * JWT token generator - RFC 7519 Compliant
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final KeyManager keyManager;
    private final AppProperties appProperties;
    private final KeyStoreRepository keyStoreRepository;
    private final UserViewRepository userViewRepository;

    /**
     * Generate access token (backward compatible - auto-fetch rol from UserView)
     *
     * @param userId User ID
     * @param sessionId Session ID
     * @param additionalClaims Additional claims
     * @return JWT access token
     */
    public String generateAccessToken(
            String userId,
            UUID sessionId,
            Map<String, Object> additionalClaims
    ) {
        // Auto-fetch rol from UserView
        Integer rol = userViewRepository.findByUserId(userId)
                .map(RoleUtil::calculateRoleBitmask)
                .orElseGet(() -> {
                    log.warn("UserView not found for userId: {}, defaulting rol to 0", userId);
                    return 0;
                });

        return generateAccessToken(userId, sessionId, rol, additionalClaims);
    }

    /**
     * Generate access token
     *
     * @param userId User ID
     * @param sessionId Session ID
     * @param rol Role bitmask (16-bit integer)
     * @param additionalClaims Additional claims
     * @return JWT access token
     */
    public String generateAccessToken(
            String userId,
            UUID sessionId,
            Integer rol,
            Map<String, Object> additionalClaims
    ) {
        log.debug("Generating access token for userId: {}, sessionId: {}, rol: {}",
                userId, sessionId, rol);

        // Get active key ID
        String kid = keyStoreRepository.findActiveKey()
                .map(KeyStore::getKid)
                .orElseThrow(() -> new TokenException(
                        ErrorCode.INTERNAL_SERVER_ERROR,
                        "No active JWT key found"
                ));

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiration = now.plus(
                appProperties.getJwt().getAccessToken().getExpirationMinutes(),
                ChronoUnit.MINUTES
        );

        Map<String, Object> claims = new HashMap<>();

        // RFC 8693 - Use 'sid' for session ID
        claims.put("sid", sessionId.toString());

        // Token type
        claims.put("typ", "access");

        // Add role bitmask
        if (rol != null) {
            claims.put("rol", rol);
        }

        // Add additional claims
        if (additionalClaims != null) {
            claims.putAll(additionalClaims);
        }

        String token = Jwts.builder()
                .setHeaderParam("kid", kid)
                .setId(UUID.randomUUID().toString())           // jti
                .setSubject(userId)                            // sub
                .setIssuer(appProperties.getJwt().getIssuer()) // iss
                .setIssuedAt(DateTimeUtil.toDate(now))         // iat
                .setExpiration(DateTimeUtil.toDate(expiration)) // exp
                .addClaims(claims)
                .signWith(keyManager.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();

        log.debug("Access token generated successfully for userId: {}", userId);
        return token;
    }

    /**
     * Generate refresh token
     * Simple opaque token (not JWT)
     *
     * @param sessionId Session ID
     * @return Refresh token
     */
    public String generateRefreshToken(UUID sessionId) {
        log.debug("Generating refresh token for sessionId: {}", sessionId);

        // Format: {UUID}-{timestamp}
        String token = UUID.randomUUID().toString() + "-" + System.currentTimeMillis();

        // Base64 encode for uniformity
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                token.getBytes()
        );
    }

    /**
     * Hash refresh token for storage
     *
     * @param refreshToken Refresh token
     * @return Hashed token
     */
    public byte[] hashRefreshToken(String refreshToken) {
        return com.strade.auth_app.util.HashUtil.sha256(refreshToken);
    }

    /**
     * Get refresh token expiration
     *
     * @return Expiration LocalDateTime
     */
//    public LocalDateTime getRefreshTokenExpiration() {
//        return LocalDateTime.now().plus(
//                appProperties.getJwt().getRefreshToken().getExpirationDays(),
//                ChronoUnit.DAYS
//        );
//    }
    public LocalDateTime getRefreshTokenExpiration() {
        return LocalDateTime.now().plusDays(
                appProperties.getJwt().getRefreshToken().getExpirationMinutes()
        );
    }
}