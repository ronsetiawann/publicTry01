package com.strade.auth_app.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * IDX WhatsApp Message Template Request
 * Endpoint: POST /api/v1/ext/message_templates
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IDXWhatsAppTemplateRequest {

    private String name;
    private String language;
    //Values: AUTHENTICATION, MARKETING, UTILITY
    private String category;
    private List<Component> components;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Component {
        //Values: HEADER, BODY, BUTTON, FOOTER
        private String type;
        //Use {{1}}, {{2}} for placeholders
        private String text;
        // Values: OTP, QUICK_REPLY, URL, PHONE_NUMBER, COPY_CODE, CATALOG, PRODUCT_LIST
        @JsonProperty("sub_type")
        private String subType;
        private List<Parameter> parameters;
    }

    /**
     * Component parameter
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Parameter {
        private String type;
        private String text;
        @JsonProperty("phone_number")
        private String phoneNumber;
        @JsonProperty("coupon_code")
        private String couponCode;
        @JsonProperty("catalog_id")
        private String catalogId;
        private String payload;
    }
}