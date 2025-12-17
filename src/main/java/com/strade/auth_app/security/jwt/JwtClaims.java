package com.strade.auth_app.security.jwt;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * JWT Claims DTO - RFC 7519 Compliant
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtClaims {

    // Standard claims (RFC 7519)
    private String jti;           // JWT ID
    private String userId;        // Subject (sub)
    private UUID sessionId;       // Session ID (sid - RFC 8693)
    private String issuer;        // Issuer (iss)
    private Long issuedAt;        // Issued At (iat)
    private Long expiration;      // Expiration (exp)

    // Custom claims
    private String typ;           // Token type (access/refresh)
    private Integer rol;          // Role bitmask (16-bit)
    private List<String> permissions;

    /**
     * Parse from JWT Claims
     */
    public static JwtClaims from(Claims claims) {
        return JwtClaims.builder()
                .jti(claims.getId())
                .userId(claims.getSubject())
                .sessionId(parseSessionId(claims))
                .issuer(claims.getIssuer())
                .issuedAt(claims.getIssuedAt() != null ? claims.getIssuedAt().getTime() / 1000 : null)
                .expiration(claims.getExpiration() != null ? claims.getExpiration().getTime() / 1000 : null)
                .typ(parseType(claims))
                .rol(parseRol(claims))
                .permissions(parsePermissions(claims))
                .build();
    }

    /**
     * Parse session ID from claims (support both 'sid' and legacy 'sessionId')
     */
    private static UUID parseSessionId(Claims claims) {
        // Try RFC 8693 standard 'sid' first
        Object sid = claims.get("sid");
        if (sid != null) {
            return UUID.fromString(sid.toString());
        }

        // Fallback to legacy 'sessionId'
        Object sessionId = claims.get("sessionId");
        if (sessionId != null) {
            return UUID.fromString(sessionId.toString());
        }

        return null;
    }

    /**
     * Parse token type from claims
     */
    private static String parseType(Claims claims) {
        Object typ = claims.get("typ");
        return typ != null ? typ.toString() : null;
    }

    /**
     * Parse role bitmask from claims
     */
    private static Integer parseRol(Claims claims) {
        Object rol = claims.get("rol");
        if (rol == null) {
            return 0;
        }

        if (rol instanceof Integer) {
            return (Integer) rol;
        }

        return Integer.parseInt(rol.toString());
    }

    /**
     * Parse permissions from claims
     */
    @SuppressWarnings("unchecked")
    private static List<String> parsePermissions(Claims claims) {
        Object perms = claims.get("permissions");
        if (perms instanceof List) {
            return (List<String>) perms;
        }
        return List.of();
    }
}