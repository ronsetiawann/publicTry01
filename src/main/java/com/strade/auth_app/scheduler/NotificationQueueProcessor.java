package com.strade.auth_app.scheduler;

import com.strade.auth_app.config.properties.SchedulerProperties;
import com.strade.auth_app.constant.AppConstants;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Process notification queue
 * Handles retry logic for failed notifications
 */
@Component
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.scheduler.notification-processor",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class NotificationQueueProcessor {

    private final NotificationQueueRepository notificationQueueRepository;
    private final SchedulerProperties schedulerProperties;
    // TODO: Inject NotificationService when implemented
    // private final NotificationService notificationService;

    /**
     * Process pending notifications
     * Runs every 2 minutes
     */
    @Scheduled(fixedRate = 120000)
    @Transactional
    public void processPendingNotifications() {
        if (!schedulerProperties.getNotificationProcessor().isProcessPending()) {
            return;
        }

        log.debug("Processing pending notifications");

        try {
            // Get pending notifications created in last 24 hours (avoid stuck items)
            LocalDateTime threshold = LocalDateTime.now().minus(24, ChronoUnit.HOURS);

            List<NotificationQueue> pendingNotifications =
                    notificationQueueRepository.findPendingNotifications(10, threshold);

            if (!pendingNotifications.isEmpty()) {
                log.info("Found {} pending notifications to process", pendingNotifications.size());

                int processed = 0;
                int failed = 0;

                for (NotificationQueue notification : pendingNotifications) {
                    try {
                        // Double check status (could have changed)
                        if (!notification.isPending()) {
                            continue;
                        }

                        processNotification(notification);
                        processed++;

                    } catch (Exception e) {
                        log.error("Error processing notification: {} - Type: {}",
                                notification.getNotificationId(),
                                notification.getType(), e);

                        handleProcessingError(notification, e);
                        failed++;
                    }
                }

                log.info("Notification processing completed - Processed: {}, Failed: {}",
                        processed, failed);
            }
        } catch (Exception e) {
            log.error("Error in notification queue processor", e);
        }
    }

    /**
     * Process single notification
     */
    private void processNotification(NotificationQueue notification) {
        log.debug("Processing notification: {} - Type: {}, Channel: {}",
                notification.getNotificationId(),
                notification.getType(),
                notification.getChannel());

        // TODO: Implement actual notification sending based on channel
        // Example implementation:
        /*
        switch (notification.getChannel().toUpperCase()) {
            case "EMAIL":
                notificationService.sendEmail(notification);
                break;
            case "SMS":
                notificationService.sendSms(notification);
                break;
            case "WHATSAPP":
                notificationService.sendWhatsApp(notification);
                break;
            default:
                throw new IllegalArgumentException("Unsupported channel: " + notification.getChannel());
        }
        */

        // For now, simulate successful send (for testing)
        notification.setStatus(AppConstants.NOTIFICATION_STATUS_SENT);
        notification.setSentAt(LocalDateTime.now());
        notification.setErrorMessage(null); // Clear any previous errors
        notificationQueueRepository.save(notification);

        log.info("Notification sent successfully: {} - Type: {}, To: {}",
                notification.getNotificationId(),
                notification.getType(),
                notification.getDestination());
    }

    /**
     * Handle processing error with retry logic
     */
    private void handleProcessingError(NotificationQueue notification, Exception error) {
        // Increment retry count
        notification.setRetryCount((byte) (notification.getRetryCount() + 1));

        String errorMessage = error.getMessage();
        if (errorMessage != null && errorMessage.length() > 500) {
            errorMessage = errorMessage.substring(0, 497) + "...";
        }
        notification.setErrorMessage(errorMessage);

        // Check if can retry
        if (notification.canRetry()) {
            // Keep status as PENDING for retry
            log.warn("Notification processing failed, will retry ({}/3): {} - Error: {}",
                    notification.getRetryCount(),
                    notification.getNotificationId(),
                    errorMessage);
        } else {
            // Max retries exceeded, mark as FAILED
            notification.setStatus(AppConstants.NOTIFICATION_STATUS_FAILED);
            log.error("Notification FAILED after {} retries: {} - Type: {} - Error: {}",
                    notification.getRetryCount(),
                    notification.getNotificationId(),
                    notification.getType(),
                    errorMessage);
        }

        notificationQueueRepository.save(notification);
    }

    /**
     * Cleanup old notifications
     * Runs daily at 5 AM
     */
    @Scheduled(cron = "0 0 5 * * *")
    @Transactional
    public void cleanupOldNotifications() {
        if (!schedulerProperties.getNotificationProcessor().isCleanupOld()) {
            log.debug("cleanupOldNotifications is disabled");
            return;
        }

        log.info("Starting cleanup of old notifications");

        try {
            LocalDateTime threshold = LocalDateTime.now().minus(30, ChronoUnit.DAYS);

            // Delete sent and failed notifications older than 30 days
            int deletedCount = notificationQueueRepository.deleteByStatusInAndCreatedAtBefore(
                    List.of(
                            AppConstants.NOTIFICATION_STATUS_SENT,
                            AppConstants.NOTIFICATION_STATUS_FAILED
                    ),
                    threshold
            );

            log.info("Completed cleanup of old notifications - Deleted: {} records", deletedCount);

            // Also cleanup very old pending notifications (stuck for more than 7 days)
            LocalDateTime stuckThreshold = LocalDateTime.now().minus(7, ChronoUnit.DAYS);
            List<NotificationQueue> stuckNotifications =
                    notificationQueueRepository.findByStatusAndCreatedAtBefore(
                            AppConstants.NOTIFICATION_STATUS_PENDING,
                            stuckThreshold
                    );

            if (!stuckNotifications.isEmpty()) {
                log.warn("Found {} stuck pending notifications (older than 7 days), marking as FAILED",
                        stuckNotifications.size());

                for (NotificationQueue notification : stuckNotifications) {
                    notification.setStatus(AppConstants.NOTIFICATION_STATUS_FAILED);
                    notification.setErrorMessage("Stuck in pending status for more than 7 days");
                    notificationQueueRepository.save(notification);
                }
            }

        } catch (Exception e) {
            log.error("Error during notification cleanup", e);
        }
    }

    /**
     * Log notification queue statistics
     * Runs every hour
     */
    @Scheduled(cron = "0 0 * * * *")
    public void logNotificationStatistics() {
        try {
            long pendingCount = notificationQueueRepository.countByStatus(
                    AppConstants.NOTIFICATION_STATUS_PENDING);
            long sentCount = notificationQueueRepository.countByStatus(
                    AppConstants.NOTIFICATION_STATUS_SENT);
            long failedCount = notificationQueueRepository.countByStatus(
                    AppConstants.NOTIFICATION_STATUS_FAILED);

            log.info("Notification Queue Statistics - Pending: {}, Sent: {}, Failed: {}",
                    pendingCount, sentCount, failedCount);

            // Alert if too many pending
            if (pendingCount > 100) {
                log.warn("HIGH number of pending notifications: {}. Check notification service!",
                        pendingCount);
            }

            // Alert if high failure rate
            if (failedCount > 50) {
                log.warn("HIGH number of failed notifications: {}. Check notification configuration!",
                        failedCount);
            }

        } catch (Exception e) {
            log.error("Error logging notification statistics", e);
        }
    }
}