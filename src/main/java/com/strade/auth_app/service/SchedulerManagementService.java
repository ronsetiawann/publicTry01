package com.strade.auth_app.service;

import com.strade.auth_app.config.properties.SchedulerProperties;
import com.strade.auth_app.dto.scheduler.SchedulerToggleRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class SchedulerManagementService {

    private final SchedulerProperties schedulerProperties;

    public Map<String, Object> getAllSchedulerStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("masterEnabled", schedulerProperties.isEnabled());
        status.put("tokenCleanup", schedulerProperties.getTokenCleanup());
        status.put("sessionCleanup", schedulerProperties.getSessionCleanup());
        status.put("securityMonitor", schedulerProperties.getSecurityMonitor());
        status.put("notificationProcessor", schedulerProperties.getNotificationProcessor());
        status.put("healthCheck", schedulerProperties.getHealthCheck());
        return status;
    }

    public void toggleScheduler(SchedulerToggleRequest request) {
        String group = request.getSchedulerGroup().toLowerCase();
        String job = request.getJobName() != null ? request.getJobName().toLowerCase() : null;
        Boolean enabled = request.getEnabled();

        log.info("Toggling scheduler - Group: {}, Job: {}, Enabled: {}", group, job, enabled);

        switch (group) {
            case "token-cleanup":
                if (job == null) {
                    schedulerProperties.getTokenCleanup().setEnabled(enabled);
                } else {
                    toggleTokenCleanupJob(job, enabled);
                }
                break;

            case "session-cleanup":
                if (job == null) {
                    schedulerProperties.getSessionCleanup().setEnabled(enabled);
                } else {
                    toggleSessionCleanupJob(job, enabled);
                }
                break;

            case "security-monitor":
                if (job == null) {
                    schedulerProperties.getSecurityMonitor().setEnabled(enabled);
                } else {
                    toggleSecurityMonitorJob(job, enabled);
                }
                break;

            case "notification-processor":
                if (job == null) {
                    schedulerProperties.getNotificationProcessor().setEnabled(enabled);
                } else {
                    toggleNotificationProcessorJob(job, enabled);
                }
                break;

            case "health-check":
                if (job == null) {
                    schedulerProperties.getHealthCheck().setEnabled(enabled);
                } else {
                    toggleHealthCheckJob(job, enabled);
                }
                break;

            default:
                throw new IllegalArgumentException("Unknown scheduler group: " + group);
        }
    }

    private void toggleTokenCleanupJob(String job, Boolean enabled) {
        SchedulerProperties.TokenCleanup tc = schedulerProperties.getTokenCleanup();
        switch (job) {
            case "expired-denylist": tc.setExpiredDenylist(enabled); break;
            case "revoked-refresh-tokens": tc.setRevokedRefreshTokens(enabled); break;
            case "expired-otp-challenges": tc.setExpiredOtpChallenges(enabled); break;
            case "old-otp-challenges": tc.setOldOtpChallenges(enabled); break;
            case "comprehensive-cleanup": tc.setComprehensiveCleanup(enabled); break;
            default: throw new IllegalArgumentException("Unknown job: " + job);
        }
    }

    private void toggleSessionCleanupJob(String job, Boolean enabled) {
        SchedulerProperties.SessionCleanup sc = schedulerProperties.getSessionCleanup();
        switch (job) {
            case "mark-inactive": sc.setMarkInactive(enabled); break;
            case "cleanup-expired": sc.setCleanupExpired(enabled); break;
            default: throw new IllegalArgumentException("Unknown job: " + job);
        }
    }

    private void toggleSecurityMonitorJob(String job, Boolean enabled) {
        SchedulerProperties.SecurityMonitor sm = schedulerProperties.getSecurityMonitor();
        switch (job) {
            case "monitor": sm.setMonitor(enabled); break;
            case "login-failures": sm.setLoginFailures(enabled); break;
            case "token-reuse": sm.setTokenReuse(enabled); break;
            default: throw new IllegalArgumentException("Unknown job: " + job);
        }
    }

    private void toggleNotificationProcessorJob(String job, Boolean enabled) {
        SchedulerProperties.NotificationProcessor np = schedulerProperties.getNotificationProcessor();
        switch (job) {
            case "process-pending": np.setProcessPending(enabled); break;
            case "cleanup-old": np.setCleanupOld(enabled); break;
            default: throw new IllegalArgumentException("Unknown job: " + job);
        }
    }

    private void toggleHealthCheckJob(String job, Boolean enabled) {
        SchedulerProperties.HealthCheck hc = schedulerProperties.getHealthCheck();
        switch (job) {
            case "database": hc.setDatabase(enabled); break;
            case "redis": hc.setRedis(enabled); break;
            default: throw new IllegalArgumentException("Unknown job: " + job);
        }
    }

    public void toggleMasterSwitch(Boolean enabled) {
        log.warn("Toggling MASTER scheduler switch to: {}", enabled);
        schedulerProperties.setEnabled(enabled);
    }
}