package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * IDX WhatsApp Broadcast Response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IDXWhatsAppBroadcastResponse {
    @JsonProperty("broadcast_id")
    private String broadcastId;
    private String name;
    @JsonProperty("template_id")
    private String templateId;
    @JsonProperty("scheduled_at")
    private String scheduledAt;
    //Values: PENDING, SCHEDULED, PROCESSING, COMPLETED, FAILED
    private String status;
    @JsonProperty("target_count")
    private Integer targetCount;
    private List<String> channels;
    @JsonProperty("created_at")
    private String createdAt;
    private String error;
}