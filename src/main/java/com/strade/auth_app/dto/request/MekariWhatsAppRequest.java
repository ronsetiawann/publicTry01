package com.strade.auth_app.dto.request;

import lombok.Data;
import java.util.List;

/**
 * Mekari Qontak WhatsApp broadcast request
 * Sesuai dengan kode C# yang diberikan
 */
@Data
public class MekariWhatsAppRequest {
    private String to_number;
    private String to_name;
    private String message_template_id;
    private String channel_integration_id;
    private Language language;
    private Parameters parameters;

    @Data
    public static class Language {
        private String code = "id";
    }

    @Data
    public static class Parameters {
        private List<BodyParameter> body;
        private List<ButtonParameter> buttons;
    }

    @Data
    public static class BodyParameter {
        private String key;
        private String value;
        private String value_text;
    }

    @Data
    public static class ButtonParameter {
        private String index;
        private String type;
        private String value;
    }
}