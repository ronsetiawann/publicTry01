package com.strade.auth_app.service;

import com.strade.auth_app.config.properties.AppProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.constant.EventTypes;
import com.strade.auth_app.dto.request.FirebaseLoginRequest;
import com.strade.auth_app.dto.request.LoginRequest;
import com.strade.auth_app.dto.request.RefreshTokenRequest;
import com.strade.auth_app.dto.response.LoginResponse;
import com.strade.auth_app.dto.response.TokenResponse;
import com.strade.auth_app.entity.Session;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.RefreshTokenRepository;
import com.strade.auth_app.repository.jpa.SessionRepository;
import com.strade.auth_app.repository.procedure.AuthProcedureRepository;
import com.strade.auth_app.repository.procedure.MfaProcedureRepository;
import com.strade.auth_app.repository.procedure.SessionProcedureRepository;
import com.strade.auth_app.repository.procedure.dto.FirebaseLoginProcedureResult;
import com.strade.auth_app.repository.procedure.dto.LoginProcedureResult;
import com.strade.auth_app.security.device.DeviceFingerprint;
import com.strade.auth_app.security.device.DeviceFingerprintExtractor;
import com.strade.auth_app.security.jwt.JwtProvider;
import com.strade.auth_app.service.cache.SessionCacheService;
import com.strade.auth_app.service.notification.EmailService;
import com.strade.auth_app.util.DateTimeUtil;
import com.strade.auth_app.util.HashUtil;
import com.strade.auth_app.util.PasswordEncryptionUtil;
import com.strade.auth_app.util.OtherUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

import static com.strade.auth_app.util.OtherUtil.firstNonBlank;
import static com.strade.auth_app.util.OtherUtil.getClientIp;

/**
 * Authentication service - WITH PASSWORD ENCRYPTION SUPPORT
 *
 * Password encryption modes (config: app.password.ledger-hash-password):
 * - "false": Plain text (no encryption)
 * - "true": TripleDES + MD5 hash (C# EncryptHash method)
 * - "simple": Simple character substitution (C# SEncrypt method)
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final AuthProcedureRepository authProcedureRepository;
    private final SessionProcedureRepository sessionProcedureRepository;
    private final MfaProcedureRepository mfaProcedureRepository;
    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionCacheService sessionCacheService;
    private final DeviceFingerprintExtractor deviceFingerprintExtractor;
    private final JwtProvider jwtProvider;
    private final MfaService mfaService;
    private final EventLogService eventLogService;
    private final LoginValidationService loginValidationService;
    private final AppProperties appProperties;
    private final PasswordHashService passwordHashService;
    private final EmailService emailService;

    /**
     * Standard login (RT/Web)
     */
    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        log.info("Login attempt: userId={}, channel={}", request.getUserId(), request.getChannel());

        try {
            // ===== 1. Ambil data dari header / request =====
            String appCode      = firstNonBlank(httpRequest.getHeader("X-App-Code"), request.getAppCode());
            String appVersion   = firstNonBlank(httpRequest.getHeader("X-App-Version"), request.getAppVersion());
            String terminalId   = firstNonBlank(httpRequest.getHeader("X-Terminal-Id"), request.getTerminalId());
            String userAgentHdr = firstNonBlank(httpRequest.getHeader("User-Agent"), request.getUserAgent());
            Integer serverNo = 0;
            // deviceId bisa dari body, kalau kosong fallback ke header
            String deviceId = request.getDeviceId();
            if (deviceId == null || deviceId.isBlank()) {
                deviceId = httpRequest.getHeader("X-Device-Id");
            }

            // ===== 2. Build device fingerprint =====
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    appCode
            );

            if (deviceId != null && !deviceId.isBlank()) {
                deviceFingerprint.setDeviceId(deviceId);
            }

            String ipAddress = getClientIp(httpRequest);
            String userAgent = (userAgentHdr != null && !userAgentHdr.isBlank())
                    ? userAgentHdr
                    : "UNKNOWN";

            // ===== 3. Process password =====
            String processedPassword = processPassword(request.getPassword());

            log.debug("Password encryption: mode={}, original={} chars, processed={} chars",
                    appProperties.getPassword().getLedgerHashPassword(),
                    request.getPassword().length(),
                    processedPassword.length());

            // ===== 4. Call SP SelectUser_Logon_v2 =====
            LoginProcedureResult result = authProcedureRepository.selectUserLogon(
                    request.getUserId(),
                    processedPassword,                  // processed (encrypted) password
                    request.getChannel(),
                    appVersion,                         // dari header X-App-Version
                    serverNo,                           // dari config
                    terminalId,                         // dari header X-Terminal-Id
                    appCode,                            // dari header X-App-Code
                    deviceFingerprint.getDeviceId(),
                    userAgent,
                    appProperties.getSecurity().getMfa().isEnforced(),
                    appProperties.getSecurity().getMinLoginHour() != null
                            ? appProperties.getSecurity().getMinLoginHour()
                            : 1,
                    appProperties.getSecurity().getMinLoginMinute() != null
                            ? appProperties.getSecurity().getMinLoginMinute()
                            : 0
            );

            // ===== 5. Handle login gagal =====
            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.warn("Login failed for userId: {} - Code: {}, Message: {}",
                        request.getUserId(), result.getErrCode(), result.getLoginMessage());

                throw new AuthException(
                        ErrorCode.fromCode(result.getErrCode()),
                        result.getLoginMessage()
                );
            }

            // ===== 6. MFA required? =====
            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                log.info("MFA required for userId: {}, sessionId: {}",
                        request.getUserId(), result.getSessionId());

                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        request.getUserId(),
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                eventLogService.logEvent(
                        request.getUserId(),
                        result.getSessionId(),
                        EventTypes.MFA_REQUIRED,
                        "MFA verification required - device not trusted"
                );

                // Send email notification for untrusted device login
                try {
                    emailService.sendUntrustedDeviceLogin(
                            request.getUserId(),
                            deviceFingerprint,  // Pass the whole fingerprint object
                            ipAddress
                    );
                } catch (Exception e) {
                    // Don't block login if email fails
                    log.error("Failed to send untrusted device login email for userId: {}",
                            request.getUserId(), e);
                }

                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        result.getLoginMessage()
                );
            }

            // ===== 7. MFA tidak required (trusted device) =====
            log.info("MFA not required for userId: {} - trusted device", request.getUserId());

            // 1) Generate tokens
            TokenResponse tokens = generateTokens(
                    request.getUserId(),
                    result.getSessionId(),
                    result.getKid()
            );

            mfaProcedureRepository.completeMfaLogin(
                    request.getUserId(),
                    result.getSessionId(),
                    result.getKid(),
                    extractJti(tokens.getAccessToken()),
                    jwtProvider.hashRefreshToken(tokens.getRefreshToken()),
                    jwtProvider.getRefreshTokenExpiration(),
                    ipAddress,
                    userAgent,
                    terminalId,
                    serverNo
            );

            // 3) Update session to ACTIVE + cache (jika method kamu return session, jangan assign kalau nggak dipakai)
            Session session = updateSessionToActive(result.getSessionId(), ipAddress, userAgent);
            if (session != null) {
                sessionCacheService.cacheSession(session);
            }

            // 4) Optional: app-level event log
            eventLogService.logEvent(
                    request.getUserId(),
                    result.getSessionId(),
                    EventTypes.LOGIN_SUCCESS,
                    "Login successful without MFA (trusted device)"
            );

            log.info("Login successful for userId: {} (no MFA required)", request.getUserId());

            return LoginResponse.success(
                    tokens,
                    result.getSessionId(),
                    result.getLoginMessage()
            );
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Login error for userId: {}", request.getUserId(), e);
            throw new AuthException(
                    ErrorCode.INTERNAL_SERVER_ERROR,
                    "Login failed due to system error"
            );
        }
    }


    /**
     * RESTORED: Firebase login // NOT USE IN STRADE
     */
    @Transactional
    public LoginResponse loginWithFirebase(
            FirebaseLoginRequest request,
            HttpServletRequest httpRequest
    ) {
        log.info("Firebase login attempt: channel={}", request.getChannel());

        try {
            DeviceFingerprint deviceFingerprint = deviceFingerprintExtractor.extract(
                    httpRequest,
                    request.getChannel(),
                    null
            );

            String ipAddress = getClientIp(httpRequest);

            FirebaseLoginProcedureResult result = authProcedureRepository.loginIdxMobile(
                    request.getFirebaseToken(),
                    null,
                    request.getTerminal(),
                    request.getChannel(),
                    request.getVersion(),
                    deviceFingerprint.getDeviceId(),
                    request.getUserAgent(),
                    ipAddress,
                    appProperties.getSecurity().getMfa().isEnforced()
            );

            if (!Boolean.TRUE.equals(result.getIsLoginSuccess())) {
                log.warn("Firebase login failed: reason={}", result.getLoginMessage());
                throw new AuthException(
                        ErrorCode.fromCode(result.getErrCode()),
                        result.getLoginMessage()
                );
            }

            Session session = sessionRepository.findBySessionId(result.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found after Firebase login"
                    ));

            String userId = session.getUserId();

            if (Boolean.TRUE.equals(result.getMfaRequired())) {
                List<String> availableMethods = mfaService.getAvailableMfaMethods(
                        userId,
                        deviceFingerprint.getDeviceId(),
                        request.getChannel()
                );

                String loginMessage = loginValidationService.getLoginMessage(userId);

                return LoginResponse.mfaRequired(
                        result.getSessionId(),
                        availableMethods,
                        loginMessage
                );
            }

            TokenResponse tokens = generateTokens(
                    userId,
                    result.getSessionId(),
                    result.getKid()
            );

            authProcedureRepository.updateSessionJti(
                    result.getSessionId(),
                    result.getKid(),
                    extractJti(tokens.getAccessToken())
            );

            Session updatedSession = updateSessionToActive(result.getSessionId(), ipAddress, request.getUserAgent());

            if (updatedSession != null) {
                sessionCacheService.cacheSession(updatedSession);
            }

            log.info("Firebase login successful: userId={}, sessionId={}",
                    userId, result.getSessionId());

            String loginMessage = loginValidationService.getLoginMessage(userId);

            return LoginResponse.success(tokens, result.getSessionId(), loginMessage);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Firebase login error", e);
            throw new AuthException(ErrorCode.FIREBASE_AUTH_FAILED, "Firebase login failed", e);
        }
    }

    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Token refresh attempt");

        try {
            byte[] tokenHash = HashUtil.sha256(request.getRefreshToken());

            //   Validate refresh token exists
            var refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.REFRESH_TOKEN_INVALID,
                            "Invalid refresh token"
                    ));

            //   Check if already revoked (basic check before SP call)
            if (refreshToken.getRevokedAt() != null) {
                log.warn("Revoked refresh token used: {}", refreshToken.getRefreshId());
                throw new AuthException(
                        ErrorCode.REFRESH_TOKEN_REVOKED,
                        "Refresh token has been revoked"
                );
            }

            //   Check if expired
            if (DateTimeUtil.isPast(refreshToken.getExpiresAt())) {
                log.warn("Expired refresh token used: {}", refreshToken.getRefreshId());
                throw new AuthException(
                        ErrorCode.REFRESH_TOKEN_EXPIRED,
                        "Refresh token has expired"
                );
            }

            //   Get session
            Session session = sessionRepository.findBySessionId(refreshToken.getSessionId())
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            //   Check session status
            if (session.getStatus() != AppConstants.SESSION_STATUS_ACTIVE) {
                throw new AuthException(
                        ErrorCode.SESSION_INACTIVE,
                        "Session is not active"
                );
            }

            //   Generate new tokens
            String newAccessToken = jwtProvider.generateAccessToken(
                    session.getUserId(),
                    session.getSessionId(),
                    null
            );

            String newRefreshToken = jwtProvider.generateRefreshToken(session.getSessionId());
            byte[] newRefreshHash = jwtProvider.hashRefreshToken(newRefreshToken);
            LocalDateTime newRefreshExp = jwtProvider.getRefreshTokenExpiration();

            //   Rotate refresh token via stored procedure
            UUID newRefreshId;
            try {
                newRefreshId = sessionProcedureRepository.rotateRefreshToken(
                        tokenHash,           //   Old token hash (INPUT)
                        newRefreshHash,      //   New token hash (INPUT)
                        newRefreshExp        //   New expiration (INPUT)
                );
                // SP returns newRefreshId and internally handles sessionId

                log.debug("New refresh token created: refreshId={}", newRefreshId);

            } catch (AuthException e) {
                //   Handle token reuse detection
                if (e.getErrorCode() == ErrorCode.TOKEN_REUSE_DETECTED) {
                    log.error("⚠️ SECURITY ALERT: Refresh token reuse detected for user: {}, session: {}",
                            session.getUserId(), session.getSessionId());

                    // SP already revoked all tokens in family, just log event
                    eventLogService.logEvent(
                            session.getUserId(),
                            session.getSessionId(),
                            EventTypes.REFRESH_REUSE_DETECTED,
                            "Refresh token reuse - all sessions in token family revoked by SP"
                    );

                    // Optional: Notify user via email
                    // emailService.sendSecurityAlert(session.getUserId(), "Token reuse detected");
                }
                throw e;
            }

            //   Update session last seen
            session.setLastSeenAt(LocalDateTime.now());
            sessionRepository.save(session);
            sessionCacheService.cacheSession(session);

            log.info("  Token refreshed successfully: userId={}, sessionId={}, newRefreshId={}",
                    session.getUserId(), session.getSessionId(), newRefreshId);

            //   Return new tokens
            return TokenResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
                    .tokenType("Bearer")
                    .build();

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("❌ Token refresh error", e);
            throw new AuthException(ErrorCode.REFRESH_TOKEN_INVALID, "Token refresh failed", e);
        }
    }

    @Transactional
    public void logout(UUID sessionId, String reason) {
        log.info("Logout: sessionId={}", sessionId);

        try {
            Session session = sessionRepository.findBySessionId(sessionId)
                    .orElseThrow(() -> new AuthException(
                            ErrorCode.SESSION_NOT_FOUND,
                            "Session not found"
                    ));

            // 1. Revoke session
            sessionProcedureRepository.revokeSession(
                    sessionId,
                    reason != null ? reason : "User logout"
            );

            // 2. Update legacy logout (pass terminalId from session)
            sessionProcedureRepository.updateUserLogout(
                    session.getUserId(),
                    session.getTerminalId()  // 👈 Ambil dari session
            );

            // 3. Invalidate cache
            sessionCacheService.invalidateSession(sessionId);

            // 4. Log event
            eventLogService.logEvent(
                    session.getUserId(),
                    sessionId,
                    EventTypes.LOGOUT,
                    "User logged out"
            );

            log.info("Logout successful: sessionId={}, userId={}", sessionId, session.getUserId());

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Logout error: sessionId={}", sessionId, e);
            throw new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, "Logout failed", e);
        }
    }

    @Transactional
    public void logoutAll(String userId, UUID exceptSessionId) {
        log.info("Logout all sessions: userId={}, exceptSessionId={}", userId, exceptSessionId);

        try {
            // 1. Get terminal ID dari session yang aktif (untuk log)
            String terminalId = "UNKNOWN";
            if (exceptSessionId != null) {
                terminalId = sessionRepository.findBySessionId(exceptSessionId)
                        .map(Session::getTerminalId)
                        .orElse("UNKNOWN");
            }

            // 2. Revoke all sessions
            sessionProcedureRepository.revokeAllSessionsForUser(
                    userId,
                    exceptSessionId,
                    "User logout all sessions"
            );

            // 3. Update legacy logout
            sessionProcedureRepository.updateUserLogout(userId, terminalId);

            // 4. Invalidate cache
            sessionCacheService.invalidateUserSessions(userId);

            // 5. Log event
            eventLogService.logEvent(
                    userId,
                    exceptSessionId,
                    EventTypes.LOGOUT_ALL,
                    exceptSessionId != null
                            ? "All other sessions logged out"
                            : "All sessions logged out"
            );

            log.info("Logout all successful: userId={}", userId);

        } catch (Exception e) {
            log.error("Logout all error: userId={}", userId, e);
            throw new AuthException(ErrorCode.INTERNAL_SERVER_ERROR, "Logout all failed", e);
        }
    }

    /**
     * Process password based on configuration
     * 1. First decrypt from frontend format [ENC0...] if present
     * 2. Then encrypt for DB storage if configured
     *
     * @param password Password from frontend (may be encrypted)
     * @return Processed password for DB comparison
     */
    private String processPassword(String password) {
        if (password == null || password.isEmpty()) {
            return password;
        }

        // Step 1: Decrypt dari frontend
        String plainPassword = password;
        //String testPlainPassword = "abc123";
        if (password.startsWith("[ENC0") && password.endsWith("]")) {
            // FIX: Langsung pakai, jangan valueOf
            plainPassword = PasswordEncryptionUtil.decryptFromFrontend(
                    password,
                    appProperties.getPassword().getFrontendDecryptMode() // Sudah DecryptMode type
            );
        }

        // Step 2: Hash untuk DB
        if (plainPassword.length() <= 1) {
            return plainPassword;
        }

        String mode = appProperties.getPassword().getLedgerHashPassword();
        if (mode == null) {
            mode = "false";
        }

        switch (mode.toLowerCase()) {
            case "true":
                return passwordHashService.hashPassword(plainPassword);

            case "simple":
                return PasswordEncryptionUtil.simpleEncrypt(plainPassword);

            default:
                return plainPassword;
        }
    }

    // Helper methods
//    private TokenResponse generateTokens(String userId, UUID sessionId, String kid) {
//        String accessToken = jwtProvider.generateAccessToken(userId, sessionId, null);
//        String refreshToken = jwtProvider.generateRefreshToken(sessionId);
//        byte[] refreshHash = jwtProvider.hashRefreshToken(refreshToken);
//        LocalDateTime refreshExp = jwtProvider.getRefreshTokenExpiration();
//
//        sessionProcedureRepository.storeRefreshOnLogin(sessionId, refreshHash, refreshExp);
//
//        return TokenResponse.builder()
//                .accessToken(accessToken)
//                .refreshToken(refreshToken)
//                .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
//                .tokenType("Bearer")
//                .build();
//    }

    private TokenResponse generateTokens(String userId, UUID sessionId, String kid) {
        String accessToken = jwtProvider.generateAccessToken(userId, sessionId, null);
        String refreshToken = jwtProvider.generateRefreshToken(sessionId);

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(appProperties.getJwt().getAccessToken().getExpirationMinutes() * 60)
                .tokenType("Bearer")
                .build();
    }

    private Session updateSessionToActive(UUID sessionId, String ipAddress, String userAgent) {
        return sessionRepository.findBySessionId(sessionId)
                .map(session -> {
                    session.setStatus(AppConstants.SESSION_STATUS_ACTIVE);
                    session.setLastSeenAt(LocalDateTime.now());
                    session.setIpAddress(ipAddress);
                    session.setUserAgent(userAgent);
                    return sessionRepository.save(session);
                })
                .orElse(null);
    }

    private String extractJti(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                int jtiStart = payload.indexOf("\"jti\":\"") + 7;
                int jtiEnd = payload.indexOf("\"", jtiStart);
                return payload.substring(jtiStart, jtiEnd);
            }
        } catch (Exception e) {
            log.warn("Failed to extract JTI from token", e);
        }
        return null;
    }


}