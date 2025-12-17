package com.strade.auth_app.service.notification;

import com.strade.auth_app.dto.request.TransactionOtpSendRequest;

import java.util.Map;

/**
 * WhatsApp Service Interface
 * Abstraction layer for multiple WhatsApp providers (Mekari, IDX, etc.)
 * This allows switching between providers without changing business logic
 */
public interface WhatsAppService {

    /**
     * Send OTP via WhatsApp for Login 2FA
     *
     * @param userId User identifier
     * @param phoneNumber Recipient phone number
     * @param name Recipient name
     * @param otpCode OTP code to send
     * @return Message/Broadcast ID from provider
     */
    String sendOtp(String userId, String phoneNumber, String name, String otpCode);

    /**
     * Send transaction OTP via WhatsApp
     *
     * @param userId User identifier
     * @param phoneNumber Recipient phone number
     * @param name Recipient name
     * @param otpCode OTP code to send
     * @param transactionRequest Transaction details
     * @return Message/Broadcast ID from provider
     */
    String sendTransactionOtp(
            String userId,
            String phoneNumber,
            String name,
            String otpCode,
            TransactionOtpSendRequest transactionRequest
    );

    /**
     * Get message/broadcast status
     *
     * @param messageId Message or Broadcast ID
     * @return Status information map
     */
    Map<String, Object> getMessageStatus(String messageId);
}