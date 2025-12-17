package com.strade.auth_app.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * IDX WhatsApp Broadcast Request
 * Endpoint: POST /api/v1/ext/broadcasts
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IDXWhatsAppBroadcastRequest {
    @NotBlank(message = "Broadcast name is required")
    private String name;

    @NotBlank(message = "Template ID is required")
    @JsonProperty("template_id")
    private String templateId;

    /**
     * Optional SMS fallback template ID
     */
    @JsonProperty("sms_template_id")
    private String smsTemplateId;

    /**
     * When to send (RFC3339 with offset)
     * Example: "2025-07-10T17:00:00+07:00"
     * Defaults to now if null
     */
    @JsonProperty("scheduled_at")
    private String scheduledAt;

    /**
     * Recurrence pattern: "no", "every_week", "every_month", "every_year"
     * Default: "no"
     */
    private String recurrence = "no";

    /**
     * Send channels (e.g., ["whatsapp", "sms"])
     * Default: both channels
     */
    private List<String> channels;

    /**
     * Global template values applied to all targets
     */
    @JsonProperty("global_template_values")
    private GlobalTemplateValues globalTemplateValues;

    /**
     * List of target recipients (required)
     */
    private List<Target> targets;

    /**
     * Validate only without sending
     */
    @JsonProperty("dry_run")
    private Boolean dryRun;

    /**
     * Global template values structure
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GlobalTemplateValues {
        /**
         * Header parameters (for media)
         */
        private HeaderParams header;

        /**
         * Body parameters
         */
        private BodyParams body;

        /**
         * Button parameters
         * Key is button index (e.g., "0")
         */
        @JsonProperty("button_params")
        private Map<String, String> buttonParams;
    }

    /**
     * Header parameters (for image/document)
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HeaderParams {
        /**
         * Media ID from Upload Media endpoint
         */
        @JsonProperty("media_id")
        private String mediaId;

        /**
         * Or direct media link
         */
        @JsonProperty("media_link")
        private String mediaLink;
    }

    /**
     * Body parameters (positional arguments)
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BodyParams {
        /**
         * Positional arguments for body placeholders
         * Example: ["654321"] for {{1}}
         */
        @JsonProperty("positional_args")
        private List<String> positionalArgs;
    }

    /**
     * Target recipient
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Target {
        /**
         * Phone number with country code
         * Example: "+6281234567890"
         */
        @JsonProperty("phone_number")
        private String phoneNumber;

        /**
         * Optional per-target template values (overrides global)
         */
        @JsonProperty("template_values")
        private TemplateValues templateValues;
    }

    /**
     * Per-target template values
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TemplateValues {
        private BodyParams body;

        @JsonProperty("button_params")
        private Map<String, String> buttonParams;
    }
}