package com.strade.auth_app.security;

import com.strade.auth_app.security.jwt.JwtClaims;
import com.strade.auth_app.util.RoleUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Authentication context for current request
 * Stored in Spring Security Context
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationContext {

    private String userId;
    private UUID sessionId;
    private String jti;
    private List<String> permissions;
    private boolean authenticated;
    private Integer rol; // Role bitmask (16-bit)

    // Additional metadata
    private String channel;
    private String deviceId;
    private String ipAddress;

    /**
     * Create from JWT claims
     */
    public static AuthenticationContext fromJwtClaims(JwtClaims claims) {
        return AuthenticationContext.builder()
                .userId(claims.getUserId())
                .sessionId(claims.getSessionId())
                .jti(claims.getJti())
                .permissions(claims.getPermissions())
                .rol(claims.getRol()) // Add this line
                .authenticated(true)
                .build();
    }

    /**
     * Get authorities for Spring Security
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (permissions == null || permissions.isEmpty()) {
            return List.of();
        }
        return permissions.stream()
                .map(perm -> (GrantedAuthority) () -> perm)
                .toList();
    }

    /**
     * Check if user has specific permission
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Check if user has any of the permissions
     */
    public boolean hasAnyPermission(String... permissions) {
        if (this.permissions == null || this.permissions.isEmpty()) {
            return false;
        }
        for (String permission : permissions) {
            if (this.permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has specific role using bitmask
     */
    public boolean hasRole(int roleFlag) {
        return rol != null && RoleUtil.hasRole(rol, roleFlag);
    }

    /**
     * Check if user has any of the specified roles
     */
    public boolean hasAnyRole(int... roleFlags) {
        return rol != null && RoleUtil.hasAnyRole(rol, roleFlags);
    }

    /**
     * Check if user has all of the specified roles
     */
    public boolean hasAllRoles(int... roleFlags) {
        return rol != null && RoleUtil.hasAllRoles(rol, roleFlags);
    }

    /**
     * Check if user is Sales
     */
    public boolean isSales() {
        return hasRole(RoleUtil.ROLE_SALES);
    }

    /**
     * Check if user is Dealer
     */
    public boolean isDealer() {
        return hasRole(RoleUtil.ROLE_DEALER);
    }

    /**
     * Check if user is Client
     */
    public boolean isClient() {
        return hasRole(RoleUtil.ROLE_CLIENT);
    }

    /**
     * Check if user is Controller
     */
    public boolean isController() {
        return hasRole(RoleUtil.ROLE_CONTROLLER);
    }

    /**
     * Check if user is Supervisor
     */
    public boolean isSupervisor() {
        return hasRole(RoleUtil.ROLE_SUPERVISOR);
    }

    /**
     * Get human-readable role names
     */
    public String getRoleNames() {
        return rol != null ? RoleUtil.getRoleNames(rol) : "No Roles";
    }
}