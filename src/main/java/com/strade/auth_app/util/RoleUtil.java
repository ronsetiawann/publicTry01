package com.strade.auth_app.util;

import com.strade.auth_app.entity.UserView;

/**
 * Utility class for role bitmask operations
 */
public class RoleUtil {

    // Bit positions (16-bit integer)
    public static final int ROLE_SALES = 1;       // 2^0 = 0b00001
    public static final int ROLE_DEALER = 2;      // 2^1 = 0b00010
    public static final int ROLE_CLIENT = 4;      // 2^2 = 0b00100
    public static final int ROLE_CONTROLLER = 8;  // 2^3 = 0b01000
    public static final int ROLE_SUPERVISOR = 16; // 2^4 = 0b10000

    private RoleUtil() {
        // Utility class, prevent instantiation
    }

    /**
     * Convert UserView roles to 16-bit integer bitmask
     *
     * @param userView User view entity
     * @return Role bitmask
     */
    public static int calculateRoleBitmask(UserView userView) {
        if (userView == null) {
            return 0;
        }

        int rol = 0;

        if (Boolean.TRUE.equals(userView.getAsSales())) {
            rol |= ROLE_SALES;
        }
        if (Boolean.TRUE.equals(userView.getAsDealer())) {
            rol |= ROLE_DEALER;
        }
        if (Boolean.TRUE.equals(userView.getAsClient())) {
            rol |= ROLE_CLIENT;
        }
        if (Boolean.TRUE.equals(userView.getAsController())) {
            rol |= ROLE_CONTROLLER;
        }
        if (Boolean.TRUE.equals(userView.getAsSupervisor())) {
            rol |= ROLE_SUPERVISOR;
        }

        return rol;
    }

    /**
     * Check if role bitmask has specific role flag
     *
     * @param rolBitmask Role bitmask
     * @param roleFlag Role flag to check
     * @return true if role is present
     */
    public static boolean hasRole(int rolBitmask, int roleFlag) {
        return (rolBitmask & roleFlag) != 0;
    }

    /**
     * Check if role bitmask has any of the specified roles
     *
     * @param rolBitmask Role bitmask
     * @param roleFlags Role flags to check
     * @return true if any role is present
     */
    public static boolean hasAnyRole(int rolBitmask, int... roleFlags) {
        for (int flag : roleFlags) {
            if (hasRole(rolBitmask, flag)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if role bitmask has all of the specified roles
     *
     * @param rolBitmask Role bitmask
     * @param roleFlags Role flags to check
     * @return true if all roles are present
     */
    public static boolean hasAllRoles(int rolBitmask, int... roleFlags) {
        for (int flag : roleFlags) {
            if (!hasRole(rolBitmask, flag)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get human-readable role names from bitmask
     *
     * @param rolBitmask Role bitmask
     * @return Comma-separated role names
     */
    public static String getRoleNames(int rolBitmask) {
        if (rolBitmask == 0) {
            return "No Roles";
        }

        StringBuilder roles = new StringBuilder();

        if (hasRole(rolBitmask, ROLE_SALES)) {
            roles.append("Sales, ");
        }
        if (hasRole(rolBitmask, ROLE_DEALER)) {
            roles.append("Dealer, ");
        }
        if (hasRole(rolBitmask, ROLE_CLIENT)) {
            roles.append("Client, ");
        }
        if (hasRole(rolBitmask, ROLE_CONTROLLER)) {
            roles.append("Controller, ");
        }
        if (hasRole(rolBitmask, ROLE_SUPERVISOR)) {
            roles.append("Supervisor, ");
        }

        // Remove trailing comma and space
        if (roles.length() > 0) {
            roles.setLength(roles.length() - 2);
        }

        return roles.toString();
    }
}