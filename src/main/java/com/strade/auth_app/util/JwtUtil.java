package com.strade.auth_app.util;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class JwtUtil {

    /**
     * Extract sessionId from JWT claims in SecurityContext
     */
    public static String getSessionIdFromToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user found");
        }

        Object principal = auth.getPrincipal();

        // If principal is Claims object
        if (principal instanceof Claims) {
            Claims claims = (Claims) principal;
            String sessionId = claims.get("sessionId", String.class);

            if (sessionId == null || sessionId.isEmpty()) {
                throw new IllegalStateException("No sessionId found in token");
            }

            return sessionId;
        }

        throw new IllegalStateException("Invalid authentication principal type: " + principal.getClass());
    }

    /**
     * Extract username from JWT claims
     */
    public static String getUsernameFromToken() {
        Claims claims = getClaimsFromContext();
        return claims.getSubject();
    }

    /**
     * Extract any claim from JWT
     */
    public static <T> T getClaimFromToken(String claimName, Class<T> clazz) {
        Claims claims = getClaimsFromContext();
        return claims.get(claimName, clazz);
    }

    /**
     * Get Claims from SecurityContext
     */
    private static Claims getClaimsFromContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user found");
        }

        Object principal = auth.getPrincipal();

        if (!(principal instanceof Claims)) {
            throw new IllegalStateException("Invalid authentication principal type");
        }

        return (Claims) principal;
    }
}