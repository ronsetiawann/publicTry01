package com.strade.auth_app.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request DTO for TOTP action verification
 * Used for verifying sensitive operations (transactions, settings changes, etc.)
 */
@Data
public class TotpActionVerifyRequest {

    /**
     * TOTP code from authenticator app (6 digits)
     */
    @NotBlank(message = "TOTP code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "TOTP code must be 6 digits")
    private String code;

    /**
     * Action type being verified
     * Examples: TRANSACTION, PASSWORD_CHANGE, WITHDRAWAL, SETTINGS_CHANGE
     */
    @NotBlank(message = "Action type is required")
    @Size(max = 50, message = "Action type too long")
    private String actionType;

    /**
     * Optional action identifier (transaction ID, etc.)
     */
    @Size(max = 100, message = "Action ID too long")
    private String actionId;

    /**
     * Optional additional context
     */
    @Size(max = 500, message = "Context too long")
    private String context;
}