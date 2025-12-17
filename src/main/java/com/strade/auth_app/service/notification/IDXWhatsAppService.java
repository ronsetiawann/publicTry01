package com.strade.auth_app.service.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.strade.auth_app.config.properties.IDXWhatsAppProperties;
import com.strade.auth_app.dto.request.IDXWhatsAppBroadcastRequest;
import com.strade.auth_app.dto.request.TransactionOtpSendRequest;
import com.strade.auth_app.dto.response.IDXWhatsAppBroadcastResponse;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import com.strade.auth_app.util.JsonUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * IDX WhatsApp Business Service
 * Provider: Indonesia Stock Exchange (IDX)
 *
 * This service integrates with IDX WhatsApp Business API for sending OTP messages
 */
@Service
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(name = "whatsapp.provider", havingValue = "idx")
public class IDXWhatsAppService implements WhatsAppService {

    private final IDXWhatsAppProperties idxProperties;
    private final RestTemplate restTemplate;
    private final NotificationQueueRepository notificationQueueRepository;
    private final ObjectMapper objectMapper;

    private static final DateTimeFormatter RFC3339_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    /**
     * Send OTP via WhatsApp (for Login 2FA)
     */
    @Override
    public String sendOtp(String userId, String phoneNumber, String name, String otpCode) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending WhatsApp OTP via IDX to {} for user {}", phoneNumber, userId);

            // Format phone number
            String formattedPhone = formatPhoneNumber(phoneNumber);

            // 1. Create notification queue entry (PENDING)
            NotificationQueue notification = createNotificationQueue(
                    notificationId,
                    userId,
                    formattedPhone,
                    name,
                    otpCode
            );
            notificationQueueRepository.save(notification);

            // 2. Build broadcast request
            IDXWhatsAppBroadcastRequest request = buildOtpBroadcastRequest(
                    formattedPhone,
                    name,
                    otpCode
            );

            // 3. Send to IDX
            HttpEntity<IDXWhatsAppBroadcastRequest> entity = new HttpEntity<>(
                    request,
                    buildHttpHeaders()
            );

            ResponseEntity<IDXWhatsAppBroadcastResponse> response = restTemplate.exchange(
                    idxProperties.getBaseUrl() + "broadcasts",
                    HttpMethod.POST,
                    entity,
                    IDXWhatsAppBroadcastResponse.class
            );

            // 4. Check response
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                IDXWhatsAppBroadcastResponse broadcastResponse = response.getBody();
                String broadcastId = broadcastResponse.getBroadcastId();

                // 5. Update notification status to SENT
                notification.setStatus((byte) 1);
                notification.setSentAt(LocalDateTime.now());
                notificationQueueRepository.save(notification);

                log.info("WhatsApp OTP sent successfully via IDX. NotificationId: {}, BroadcastId: {}",
                        notificationId, broadcastId);

                return broadcastId;
            } else {
                throw new AuthException(
                        ErrorCode.WHATSAPP_SEND_FAILED,
                        "IDX returned status: " + response.getStatusCode()
                );
            }

        } catch (RestClientException e) {
            log.error("Failed to send WhatsApp OTP via IDX for user {}", userId, e);

            // Update notification status to FAILED
            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2);
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(
                    ErrorCode.WHATSAPP_SEND_FAILED,
                    "WhatsApp send failed via IDX",
                    e
            );
        }
    }

    /**
     * Send transaction OTP via WhatsApp
     */
    @Override
    public String sendTransactionOtp(
            String userId,
            String phoneNumber,
            String name,
            String otpCode,
            TransactionOtpSendRequest transactionRequest
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending transaction OTP via IDX to {} for user {}", phoneNumber, userId);

            // Format phone
            String formattedPhone = formatPhoneNumber(phoneNumber);

            // Create notification queue
            NotificationQueue notification = createTransactionNotificationQueue(
                    notificationId,
                    userId,
                    formattedPhone,
                    name,
                    otpCode,
                    transactionRequest
            );
            notificationQueueRepository.save(notification);

            // Build broadcast request
            IDXWhatsAppBroadcastRequest request = buildOtpBroadcastRequest(
                    formattedPhone,
                    name,
                    otpCode
            );

            // Send via IDX
            HttpEntity<IDXWhatsAppBroadcastRequest> entity = new HttpEntity<>(
                    request,
                    buildHttpHeaders()
            );

            ResponseEntity<IDXWhatsAppBroadcastResponse> response = restTemplate.exchange(
                    idxProperties.getBaseUrl() + "broadcasts",
                    HttpMethod.POST,
                    entity,
                    IDXWhatsAppBroadcastResponse.class
            );

            // Check response
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String broadcastId = response.getBody().getBroadcastId();

                // Update status to SENT
                notification.setStatus((byte) 1);
                notification.setSentAt(LocalDateTime.now());
                notificationQueueRepository.save(notification);

                log.info("Transaction OTP sent successfully via IDX: broadcastId={}", broadcastId);
                return broadcastId;
            } else {
                throw new AuthException(
                        ErrorCode.WHATSAPP_SEND_FAILED,
                        "IDX returned status: " + response.getStatusCode()
                );
            }

        } catch (RestClientException e) {
            log.error("Failed to send transaction OTP via IDX", e);

            notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
                notif.setStatus((byte) 2);
                notif.setErrorMessage(e.getMessage());
                notif.setRetryCount((byte) (notif.getRetryCount() + 1));
                notificationQueueRepository.save(notif);
            });

            throw new AuthException(
                    ErrorCode.WHATSAPP_SEND_FAILED,
                    "Failed to send transaction OTP via IDX",
                    e
            );
        }
    }

    /**
     * Get broadcast status
     */
    @Override
    public Map<String, Object> getMessageStatus(String broadcastId) {
        try {
            HttpEntity<Void> entity = new HttpEntity<>(buildHttpHeaders());

            ResponseEntity<String> response = restTemplate.exchange(
                    idxProperties.getBaseUrl() + "broadcasts/" + broadcastId,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                return JsonUtil.toMap(response.getBody());
            }

            return Map.of("error", "Failed to get broadcast status");

        } catch (Exception e) {
            log.error("Failed to get broadcast status for ID: {}", broadcastId, e);
            return Map.of("error", e.getMessage());
        }
    }

    /**
     * Build OTP broadcast request for IDX API
     */
    private IDXWhatsAppBroadcastRequest buildOtpBroadcastRequest(
            String phoneNumber,
            String name,
            String otpCode
    ) {
        // Build global template values
        IDXWhatsAppBroadcastRequest.BodyParams bodyParams =
                IDXWhatsAppBroadcastRequest.BodyParams.builder()
                        .positionalArgs(List.of(otpCode))
                        .build();

        // Button parameters for OTP button (index 0)
        Map<String, String> buttonParams = new HashMap<>();
        buttonParams.put("0", otpCode);

        IDXWhatsAppBroadcastRequest.GlobalTemplateValues globalValues =
                IDXWhatsAppBroadcastRequest.GlobalTemplateValues.builder()
                        .body(bodyParams)
                        .buttonParams(buttonParams)
                        .build();

        // Build target
        IDXWhatsAppBroadcastRequest.Target target =
                IDXWhatsAppBroadcastRequest.Target.builder()
                        .phoneNumber(phoneNumber)
                        .build();

        // Build broadcast request
        return IDXWhatsAppBroadcastRequest.builder()
                .name("OTP_" + System.currentTimeMillis())
                .templateId(idxProperties.getTemplate().getOtpTemplateId())
                .scheduledAt(getCurrentTimestamp())
                .recurrence("no")
                .channels(List.of("whatsapp"))
                .globalTemplateValues(globalValues)
                .targets(List.of(target))
                .dryRun(false)
                .build();
    }

    /**
     * Build HTTP headers with Bearer token
     */
    private HttpHeaders buildHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + idxProperties.getBearerToken());
        return headers;
    }

    /**
     * Get current timestamp in RFC3339 format with timezone
     */
    private String getCurrentTimestamp() {
        return LocalDateTime.now()
                .atZone(ZoneId.of("Asia/Jakarta"))
                .format(RFC3339_FORMATTER);
    }

    /**
     * Create notification queue entry (for Login 2FA)
     */
    private NotificationQueue createNotificationQueue(
            UUID notificationId,
            String userId,
            String phoneNumber,
            String name,
            String otpCode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("phone_number", phoneNumber);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);
        templateData.put("template_id", idxProperties.getTemplate().getOtpTemplateId());
        templateData.put("provider", "idx");

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_LOGIN_2FA")
                .channel("whatsapp")
                .destination(phoneNumber)
                .subject("Login OTP")
                .body("Your OTP code is: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Create notification queue for transaction OTP
     */
    private NotificationQueue createTransactionNotificationQueue(
            UUID notificationId,
            String userId,
            String phoneNumber,
            String name,
            String otpCode,
            TransactionOtpSendRequest request
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("phone_number", phoneNumber);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);
        templateData.put("purpose", request.getPurpose());
        templateData.put("provider", "idx");

        if (request.getReference() != null && !request.getReference().isEmpty()) {
            templateData.put("reference", request.getReference());
        }

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_TRANSACTION_" + request.getPurpose().toUpperCase())
                .channel("whatsapp")
                .destination(phoneNumber)
                .subject("Transaction OTP")
                .body("Transaction OTP code: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Format phone number for IDX WhatsApp
     * Converts to international format with + prefix
     */
    private String formatPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Phone number is required"
            );
        }

        // Remove all non-numeric characters
        String cleaned = phoneNumber.replaceAll("[^0-9]", "");

        // Handle different formats
        if (cleaned.startsWith("0")) {
            // 08123456789 -> +628123456789
            return "+62" + cleaned.substring(1);
        } else if (cleaned.startsWith("62")) {
            // 628123456789 -> +628123456789
            return "+" + cleaned;
        } else if (cleaned.startsWith("8")) {
            // 8123456789 -> +628123456789
            return "+62" + cleaned;
        } else {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Invalid phone number format"
            );
        }
    }
}