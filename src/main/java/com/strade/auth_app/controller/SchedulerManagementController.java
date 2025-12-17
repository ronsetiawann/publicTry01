package com.strade.auth_app.controller;

import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.dto.scheduler.SchedulerToggleRequest;
import com.strade.auth_app.entity.UserView;
import com.strade.auth_app.service.SchedulerManagementService;
import com.strade.auth_app.util.RoleUtil;
import com.strade.auth_app.util.SecurityUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

/**
 * Scheduler Management REST API Controller
 */
@RestController
@RequestMapping("/api/scheduler")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Scheduler Management", description = "Scheduler Management APIs for Admins")
public class SchedulerManagementController {

    private final SchedulerManagementService schedulerManagementService;
    private final SecurityUtils securityUtils;

    /**
     * Check if current user has SUPERVISOR or CONTROLLER role
     */
    private void checkAdminAccess() {
        String userId = securityUtils.getCurrentUserId();

        if (userId == null) {
            log.warn("Unauthorized access attempt to scheduler management");
            throw new SecurityException("Authentication required");
        }

        Optional<UserView> userOpt = securityUtils.getCurrentUser();
        if (userOpt.isEmpty()) {
            log.warn("User {} not found in system", userId);
            throw new SecurityException("User not found");
        }

        UserView currentUser = userOpt.get();
        int rolBitmask = RoleUtil.calculateRoleBitmask(currentUser);

        if (!RoleUtil.hasAnyRole(rolBitmask, RoleUtil.ROLE_SUPERVISOR, RoleUtil.ROLE_CONTROLLER)) {
            log.warn("User {} attempted to access scheduler management without proper role. Roles: {}",
                    userId, RoleUtil.getRoleNames(rolBitmask));
            throw new SecurityException("Access denied. SUPERVISOR or CONTROLLER role required");
        }
    }

    /**
     * Get all scheduler status
     * GET /api/admin/scheduler/status
     */
    @GetMapping("/status")
    @Operation(summary = "Get scheduler status", description = "Get status of all scheduler groups and jobs")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSchedulerStatus() {
        try {
            checkAdminAccess();

            String userId = securityUtils.getCurrentUserId();
            log.debug("Get scheduler status: userId={}", userId);

            Map<String, Object> status = schedulerManagementService.getAllSchedulerStatus();

            return ResponseEntity.ok(ApiResponse.success(status));

        } catch (SecurityException e) {
            log.warn("Access denied for scheduler status: {}", e.getMessage());
            return ResponseEntity.status(403).body(
                    ApiResponse.error(403, e.getMessage())
            );
        } catch (Exception e) {
            log.error("Error getting scheduler status", e);
            return ResponseEntity.status(500).body(
                    ApiResponse.error(500, "Internal server error")
            );
        }
    }

    /**
     * Toggle specific scheduler or job
     * POST /api/admin/scheduler/toggle
     */
    @PostMapping("/toggle")
    @Operation(
            summary = "Toggle scheduler",
            description = "Enable or disable specific scheduler group or job. " +
                    "Examples:\n" +
                    "1. Disable entire group: {\"schedulerGroup\": \"token-cleanup\", \"enabled\": false}\n" +
                    "2. Disable specific job: {\"schedulerGroup\": \"token-cleanup\", \"jobName\": \"expired-denylist\", \"enabled\": false}"
    )
    public ResponseEntity<ApiResponse<String>> toggleScheduler(
            @Valid @RequestBody SchedulerToggleRequest request
    ) {
        try {
            checkAdminAccess();

            String userId = securityUtils.getCurrentUserId();
            log.info("Toggle scheduler: userId={}, request={}", userId, request);

            schedulerManagementService.toggleScheduler(request);

            String message = request.getJobName() != null
                    ? String.format("Job '%s' in group '%s' %s",
                    request.getJobName(),
                    request.getSchedulerGroup(),
                    request.getEnabled() ? "enabled" : "disabled")
                    : String.format("Scheduler group '%s' %s",
                    request.getSchedulerGroup(),
                    request.getEnabled() ? "enabled" : "disabled");

            return ResponseEntity.ok(ApiResponse.success(message));

        } catch (SecurityException e) {
            log.warn("Access denied for scheduler toggle: {}", e.getMessage());
            return ResponseEntity.status(403).body(
                    ApiResponse.error(403, e.getMessage())
            );
        } catch (IllegalArgumentException e) {
            log.error("Invalid scheduler toggle request: {}", e.getMessage());
            return ResponseEntity.status(400).body(
                    ApiResponse.error(400, e.getMessage())
            );
        } catch (Exception e) {
            log.error("Error toggling scheduler", e);
            return ResponseEntity.status(500).body(
                    ApiResponse.error(500, "Internal server error")
            );
        }
    }

    /**
     * Master switch - enable/disable ALL schedulers
     * POST /api/admin/scheduler/master
     */
    @PostMapping("/master")
    @Operation(
            summary = "Toggle master scheduler switch",
            description = "Enable or disable ALL scheduler groups. Use with caution!"
    )
    public ResponseEntity<ApiResponse<String>> toggleMasterSwitch(
            @RequestParam Boolean enabled
    ) {
        try {
            checkAdminAccess();

            String userId = securityUtils.getCurrentUserId();
            log.warn("CRITICAL: Master scheduler toggle: userId={}, enabled={}", userId, enabled);

            schedulerManagementService.toggleMasterSwitch(enabled);

            String message = String.format(
                    "Master scheduler switch set to: %s. WARNING: This affects ALL scheduled tasks!",
                    enabled
            );

            return ResponseEntity.ok(ApiResponse.success(message));

        } catch (SecurityException e) {
            log.warn("Access denied for master switch: {}", e.getMessage());
            return ResponseEntity.status(403).body(
                    ApiResponse.error(403, e.getMessage())
            );
        } catch (Exception e) {
            log.error("Error toggling master switch", e);
            return ResponseEntity.status(500).body(
                    ApiResponse.error(500, "Internal server error")
            );
        }
    }

    /**
     * Get scheduler groups info
     * GET /api/admin/scheduler/groups
     */
    @GetMapping("/groups")
    @Operation(
            summary = "Get scheduler groups",
            description = "Get list of all available scheduler groups and their jobs"
    )
    public ResponseEntity<ApiResponse<Map<String, String[]>>> getSchedulerGroups() {
        try {
            checkAdminAccess();

            String userId = securityUtils.getCurrentUserId();
            log.debug("Get scheduler groups: userId={}", userId);

            Map<String, String[]> groups = Map.of(
                    "token-cleanup", new String[]{
                            "expired-denylist",
                            "revoked-refresh-tokens",
                            "expired-otp-challenges",
                            "old-otp-challenges",
                            "comprehensive-cleanup"
                    },
                    "session-cleanup", new String[]{
                            "mark-inactive",
                            "cleanup-expired"
                    },
                    "security-monitor", new String[]{
                            "monitor",
                            "login-failures",
                            "token-reuse"
                    },
                    "notification-processor", new String[]{
                            "process-pending",
                            "cleanup-old"
                    },
                    "health-check", new String[]{
                            "database",
                            "redis"
                    }
            );

            return ResponseEntity.ok(ApiResponse.success(groups));

        } catch (SecurityException e) {
            log.warn("Access denied for scheduler groups: {}", e.getMessage());
            return ResponseEntity.status(403).body(
                    ApiResponse.error(403, e.getMessage())
            );
        } catch (Exception e) {
            log.error("Error getting scheduler groups", e);
            return ResponseEntity.status(500).body(
                    ApiResponse.error(500, "Internal server error")
            );
        }
    }
}