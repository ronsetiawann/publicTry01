package com.strade.auth_app.service;

import com.strade.auth_app.dto.response.TrustedDeviceListResponse;
import com.strade.auth_app.dto.response.TrustedDeviceResponse;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.TrustedDeviceRepository;
import com.strade.auth_app.repository.procedure.DeviceProcedureRepository;
import com.strade.auth_app.service.cache.TrustedDeviceCacheService;
import com.strade.auth_app.service.notification.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Trusted device management service
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final DeviceProcedureRepository deviceProcedureRepository;
    private final TrustedDeviceCacheService trustedDeviceCacheService;
    private final EmailService emailService;

    /**
     * Check if device is trusted
     */
    public boolean isTrustedDevice(String userId, String deviceId, String channel) {
        try {
            // Check cache first
            Boolean cached = trustedDeviceCacheService.getCachedTrustedDevice(userId, deviceId, channel);
            if (cached != null) {
                log.debug("Trusted device cache hit: userId={}, deviceId={}", userId, deviceId);
                return cached;
            }

            // Check database
            boolean isTrusted = trustedDeviceRepository.existsActiveTrustedDevice(
                    userId,
                    deviceId,
                    channel,
                    LocalDateTime.now()
            );

            // Cache result
            trustedDeviceCacheService.cacheTrustedDevice(userId, deviceId, channel, isTrusted);

            return isTrusted;

        } catch (Exception e) {
            log.error("Error checking trusted device: userId={}, deviceId={}, error={}",
                    userId, deviceId, e.getMessage(), e);
            // Return false on error - device not trusted by default
            return false;
        }
    }

    /**
     * List trusted devices for user
     */
    public TrustedDeviceListResponse listTrustedDevices(String userId) {
        try {
            log.debug("Listing trusted devices for user: {}", userId);

            LocalDateTime now = LocalDateTime.now();
            var devices = trustedDeviceRepository.findActiveTrustedDevicesByUserId(userId, now);

            List<TrustedDeviceResponse> deviceResponses = devices.stream()
                    .map(device -> TrustedDeviceResponse.builder()
                            .trustedDeviceId(device.getTrustedDeviceId())
                            .deviceId(device.getDeviceId())
                            .deviceName(device.getDeviceName())
                            .deviceType(device.getDeviceType())
                            .channel(device.getTrustedChannel())
                            .trustedSetAt(device.getTrustedSetAt())
                            .trustedUntil(device.getTrustedUntil())
                            .isCurrentlyValid(device.isActive())
                            .trustedByMfaMethod(device.getTrustedByMfaMethod())
                            .build())
                    .collect(Collectors.toList());

            long totalCount = trustedDeviceRepository.countActiveTrustedDevicesByUserId(userId, now);

            log.info("Found {} trusted devices for user: {}", totalCount, userId);

            return TrustedDeviceListResponse.builder()
                    .devices(deviceResponses)
                    .totalCount((int) totalCount)
                    .activeCount(deviceResponses.size())
                    .maxAllowed(3) // From config
                    .availableSlots(Math.max(0, 3 - (int) totalCount))
                    .build();

        } catch (Exception e) {
            log.error("Error listing trusted devices for user: {}, error={}",
                    userId, e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Failed to retrieve trusted devices",
                    e
            );
        }
    }

    /**
     * Untrust a specific device
     */
    @Transactional
    public void untrustDevice(String userId, String deviceId, String channel) {
        try {
            log.info("Untrusting device: userId={}, deviceId={}, channel={}",
                    userId, deviceId, channel);

            // Validate device exists and is currently trusted
            boolean deviceExists = trustedDeviceRepository.existsActiveTrustedDevice(
                    userId,
                    deviceId,
                    channel,
                    LocalDateTime.now()
            );

            if (!deviceExists) {
                log.warn("Device not found or already untrusted: userId={}, deviceId={}",
                        userId, deviceId);
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "Device not found or already removed"
                );
            }

            // 🆕 Get device info before removal
            Map<String, String> deviceInfo = getDeviceInfo(userId, deviceId, channel);

            // Call stored procedure
            deviceProcedureRepository.untrustDevice(userId, deviceId, channel, true);

            // Invalidate cache
            trustedDeviceCacheService.invalidateTrustedDevice(userId, deviceId, channel);

            // 🆕 Send email notification (async to not block transaction)
            try {
                emailService.sendDeviceSecurityNotification(
                        userId,
                        deviceInfo.get("deviceName"),
                        deviceInfo.get("deviceType"),
                        deviceInfo.get("platform"),
                        "REMOVED"
                );
            } catch (Exception e) {
                log.error("Failed to send device removal email for userId: {}", userId, e);
            }

            log.info("Device untrusted successfully: userId={}, deviceId={}", userId, deviceId);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error untrusting device: userId={}, deviceId={}, error={}",
                    userId, deviceId, e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Failed to remove trusted device",
                    e
            );
        }
    }

    /**
     * Untrust all devices for user
     */
    @Transactional
    public void untrustAllDevices(String userId) {
        try {
            log.info("Untrusting all devices for user: {}", userId);

            // Check if user has any active trusted devices
            long activeDevicesCount = trustedDeviceRepository.countActiveTrustedDevicesByUserId(
                    userId,
                    LocalDateTime.now()
            );

            if (activeDevicesCount == 0) {
                log.warn("No active trusted devices found for user: {}", userId);
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "No trusted devices found to remove"
                );
            }

            // Call stored procedure
            deviceProcedureRepository.untrustAllDevices(userId, true);

            // Invalidate cache
            trustedDeviceCacheService.invalidateAllUserTrustedDevices(userId);

            log.info("All devices ({}) untrusted successfully for user: {}",
                    activeDevicesCount, userId);

        } catch (AuthException e) {
            // Re-throw AuthException as-is
            throw e;
        } catch (Exception e) {
            log.error("Error untrusting all devices for user: {}, error={}",
                    userId, e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Failed to remove all trusted devices",
                    e
            );
        }
    }

    /**
     * Replace old device with new device (current device)
     */
    @Transactional
    public void replaceDevice(
            String userId,
            String oldDeviceId,
            String newDeviceId,
            String channel,
            String deviceType,
            String deviceName,
            String mfaMethod,
            Integer trustTtlDays,
            Boolean sendEmailNotification
    ) {
        try {
            log.info("🔄 Replacing device: userId={}, oldDeviceId={}, newDeviceId={}, channel={}",
                    userId, oldDeviceId, newDeviceId, channel);

            // Validate old device exists
            boolean oldDeviceExists = trustedDeviceRepository.existsActiveTrustedDevice(
                    userId,
                    oldDeviceId,
                    channel,
                    LocalDateTime.now()
            );

            if (!oldDeviceExists) {
                log.warn("Old device not found or already revoked: userId={}, deviceId={}",
                        userId, oldDeviceId);
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "Device not found or already removed"
                );
            }

            // Validate new device is not already trusted
            boolean newDeviceExists = trustedDeviceRepository.existsActiveTrustedDevice(
                    userId,
                    newDeviceId,
                    channel,
                    LocalDateTime.now()
            );

            if (newDeviceExists) {
                log.warn("New device already trusted: userId={}, deviceId={}",
                        userId, newDeviceId);
                throw new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "New device is already trusted"
                );
            }

            // 🆕 Get old device info before replacement
            Map<String, String> oldDeviceInfo = getDeviceInfo(userId, oldDeviceId, channel);

            // Call stored procedure to replace device
            deviceProcedureRepository.replaceDevice(
                    userId,
                    oldDeviceId,
                    newDeviceId,
                    channel,
                    deviceType,
                    deviceName,
                    mfaMethod,
                    trustTtlDays,
                    sendEmailNotification
            );

            // Invalidate cache for old device
            trustedDeviceCacheService.invalidateTrustedDevice(userId, oldDeviceId, channel);

            // Cache new device as trusted
            trustedDeviceCacheService.cacheTrustedDevice(userId, newDeviceId, channel, true);

            // 🆕 Send email notification for replacement
            if (Boolean.TRUE.equals(sendEmailNotification)) {
                try {
                    emailService.sendDeviceReplacementNotification(
                            userId,
                            oldDeviceInfo.get("deviceName"),
                            deviceName, // new device name
                            deviceType,
                            oldDeviceInfo.get("platform")
                    );
                } catch (Exception e) {
                    log.error("Failed to send device replacement email for userId: {}", userId, e);
                }
            }

            log.info("✅ Device replaced successfully: userId={}, old={}, new={}",
                    userId, oldDeviceId, newDeviceId);

        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("❌ Error replacing device: userId={}, oldDeviceId={}, newDeviceId={}, error={}",
                    userId, oldDeviceId, newDeviceId, e.getMessage(), e);
            throw new AuthException(
                    ErrorCode.DATABASE_ERROR,
                    "Failed to replace trusted device",
                    e
            );
        }
    }

    private Map<String, String> getDeviceInfo(String userId, String deviceId, String channel) {
        return trustedDeviceRepository.findByUserIdAndDeviceIdAndChannel(
                userId, deviceId, channel
        ).map(device -> {
            Map<String, String> info = new HashMap<>();
            info.put("deviceType", device.getDeviceType() != null ? device.getDeviceType() : "Unknown");
            info.put("deviceName", device.getDeviceName() != null ? device.getDeviceName() : "Unknown Device");
            info.put("channel", device.getTrustedChannel() != null ? device.getTrustedChannel() : "Unknown");
            return info;
        }).orElse(Map.of(
                "deviceType", "Unknown",
                "deviceName", "Unknown Device",
                "channel", "Unknown"
        ));
    }
}