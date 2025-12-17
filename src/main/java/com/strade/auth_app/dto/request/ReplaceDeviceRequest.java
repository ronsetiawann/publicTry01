package com.strade.auth_app.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Replace device request")
public class ReplaceDeviceRequest {

    @NotBlank(message = "Device ID to replace is required")
    @Schema(description = "Device ID yang akan di-replace", example = "DEV213T230")
    private String deviceIdToReplace;

    @Schema(description = "Channel (optional)", example = "WB")
    private String channel;

    @Schema(description = "Device type (optional)", example = "DESKTOP")
    private String deviceType;

    @Schema(description = "Device name (optional)", example = "Chrome on Windows")
    private String deviceName;
}