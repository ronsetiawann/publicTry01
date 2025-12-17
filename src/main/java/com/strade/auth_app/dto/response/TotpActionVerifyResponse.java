package com.strade.auth_app.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for TOTP action verification
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TotpActionVerifyResponse {

    /**
     * Whether verification was successful
     */
    private Boolean verified;

    /**
     * Verification timestamp
     */
    private LocalDateTime verifiedAt;

    /**
     * Event ID for audit trail
     */
    private String eventId;

    /**
     * Message
     */
    private String message;
}