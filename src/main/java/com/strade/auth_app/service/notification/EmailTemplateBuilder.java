package com.strade.auth_app.service.notification;

import com.strade.auth_app.config.properties.EmailBrandingProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Email Template Builder
 * Builds responsive HTML email templates with configurable branding
 */
@Component
@RequiredArgsConstructor
public class EmailTemplateBuilder {

    private final EmailBrandingProperties branding;

    /**
     * Build complete email HTML with header, content, and footer
     */
    public String buildEmail(String headerTitle, String headerSubtitle, String contentHtml) {
        return String.format("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>%s</title>
                <style>
                    body,table,td,p{margin:0;padding:0;font-family:Arial,sans-serif;}
                    .wrapper{background:#f5f5f5;padding:24px;}
                    .container{max-width:600px;width:100%%;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 8px rgba(0,0,0,0.08);}
                    @media(max-width:480px){
                        .wrapper{padding:12px;}
                        .content{padding:18px 14px 20px 14px!important;}
                        h1{font-size:24px!important;}
                        p,li{font-size:13px!important;}
                    }
                </style>
            </head>
            <body>
                <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" align="center" class="wrapper">
                <tr><td align="center">
                    <table role="presentation" cellpadding="0" cellspacing="0" class="container">
                        %s
                        %s
                        %s
                    </table>
                </td></tr>
                </table>
            </body>
            </html>
            """,
                headerTitle,
                buildHeader(headerTitle, headerSubtitle),
                contentHtml,
                buildFooter()
        );
    }

    /**
     * Build email header with gradient background
     */
    public String buildHeader(String title, String subtitle) {
        return String.format("""
            <tr>
                <td style="background:%s;padding:26px 16px;text-align:center;box-shadow:0 4px 6px rgba(0,0,0,0.15);">
                    <h1 style="color:%s;margin:0;font-size:30px;font-weight:bold;">%s</h1>
                    %s
                </td>
            </tr>
            """,
                branding.getHeaderGradient(),
                branding.getTheme().getPrimaryTextColor(),
                title,
                subtitle != null ?
                        String.format("<p style=\"color:rgba(255,255,255,0.9);margin:6px 0 0 0;font-size:13px;\">%s</p>", subtitle) :
                        ""
        );
    }

    /**
     * Build email footer
     */
    public String buildFooter() {
        StringBuilder footer = new StringBuilder();

        footer.append("<tr><td style=\"background:#f8f9fa;padding:25px 20px;text-align:center;border-top:1px solid #e9ecef;\">");

        // Do not reply message
        if (branding.getFooter().isShowDoNotReply()) {
            footer.append(String.format(
                    "<p style=\"margin:0 0 8px 0;color:#666;font-size:12px;\">%s</p>",
                    branding.getFooter().getDoNotReplyText()
            ));
        }

        // Company name
        footer.append(String.format(
                "<p style=\"margin:0 0 4px 0;color:#666;font-size:12px;\"><strong>%s</strong></p>",
                branding.getCompany().getName()
        ));

        // Company description
        if (branding.getCompany().getDescription() != null) {
            footer.append(String.format(
                    "<p style=\"margin:0 0 12px 0;color:#999;font-size:11px;\">%s</p>",
                    branding.getCompany().getDescription()
            ));
        }

        // Additional text
        if (branding.getFooter().getAdditionalText() != null) {
            footer.append(String.format(
                    "<p style=\"margin:0 0 12px 0;color:#666;font-size:11px;\">%s</p>",
                    branding.getFooter().getAdditionalText()
            ));
        }

        // Copyright
        footer.append(String.format(
                "<p style=\"margin:0;color:#999;font-size:11px;\">%s</p>",
                branding.getFooter().getFullCopyrightText(branding.getApplication().getName())
        ));

        footer.append("</td></tr>");

        return footer.toString();
    }

    /**
     * Build alert box (info, warning, danger, success)
     */
    public String buildAlertBox(AlertType type, String title, String content) {
        String bgColor, borderColor, textColor;

        switch (type) {
            case SUCCESS -> {
                bgColor = "#d4edda";
                borderColor = branding.getTheme().getSuccessColor();
                textColor = "#155724";
            }
            case WARNING -> {
                bgColor = "#fff3cd";
                borderColor = branding.getTheme().getWarningColor();
                textColor = "#856404";
            }
            case DANGER -> {
                bgColor = "#f8d7da";
                borderColor = branding.getTheme().getDangerColor();
                textColor = "#721c24";
            }
            case INFO -> {
                bgColor = "#d1ecf1";
                borderColor = branding.getTheme().getInfoColor();
                textColor = "#0c5460";
            }
            default -> {
                bgColor = "#f8f9fa";
                borderColor = "#dee2e6";
                textColor = "#333";
            }
        }

        return String.format("""
            <div style="background:%s;border-left:4px solid %s;padding:18px;margin:20px 0;border-radius:4px;">
                %s
                <p style="margin:0;color:%s;font-size:14px;line-height:1.6;">%s</p>
            </div>
            """,
                bgColor,
                borderColor,
                title != null ? String.format("<h3 style=\"margin:0 0 10px 0;color:%s;font-size:16px;\">%s</h3>", textColor, title) : "",
                textColor,
                content
        );
    }

    /**
     * Build info box (neutral gray)
     */
    public String buildInfoBox(String title, String content) {
        return String.format("""
            <div style="background:#f8f9fa;border-radius:8px;padding:20px;margin:25px 0;">
                <h3 style="color:#333;margin:0 0 15px 0;font-size:18px;">%s</h3>
                <p style="margin:0;color:#555;font-size:14px;line-height:1.6;">%s</p>
            </div>
            """,
                title,
                content
        );
    }

    /**
     * Build code/key display box
     */
    public String buildCodeBox(String label, String code, String helpText) {
        return String.format("""
            <div style="background:linear-gradient(135deg,#fff5f5 0%%,#ffe0e0 100%%);border:3px solid %s;border-radius:10px;padding:20px 10px;text-align:center;margin:26px 0;">
                %s
                <h1 style="color:%s;font-size:40px;letter-spacing:10px;margin:0;font-weight:bold;font-family:'Courier New',monospace;">%s</h1>
                %s
            </div>
            """,
                branding.getTheme().getPrimaryColor(),
                label != null ? String.format("<p style=\"color:#666;font-size:11px;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:1px;\">%s</p>", label) : "",
                branding.getTheme().getPrimaryColor(),
                code,
                helpText != null ? String.format("<p style=\"color:#666;font-size:12px;margin:8px 0 0 0;\">%s</p>", helpText) : ""
        );
    }

    /**
     * Build button
     */
    public String buildButton(String text, String url, ButtonStyle style) {
        String gradient = switch (style) {
            case PRIMARY -> branding.getHeaderGradient();
            case SUCCESS -> branding.getSuccessGradient();
            case DANGER -> branding.getDangerGradient();
            case INFO -> branding.getInfoGradient();
            case WARNING -> branding.getWarningGradient();
        };

        return String.format("""
            <div style="text-align:center;margin:30px 0;">
                <a href="%s" style="display:inline-block;background:%s;color:white;padding:16px 45px;text-decoration:none;border-radius:8px;font-size:16px;font-weight:bold;box-shadow:0 4px 12px rgba(0,0,0,0.2);">%s</a>
            </div>
            """,
                url,
                gradient,
                text
        );
    }

    /**
     * Build details table
     */
    public String buildDetailsTable(String... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("Key-value pairs must be even");
        }

        StringBuilder table = new StringBuilder();
        table.append("<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">");

        for (int i = 0; i < keyValues.length; i += 2) {
            String key = keyValues[i];
            String value = keyValues[i + 1];

            table.append(String.format("""
                <tr>
                    <td style="padding:6px 0;color:#666;font-size:14px;width:140px;">%s:</td>
                    <td style="padding:6px 0;color:#333;font-size:14px;font-weight:500;">%s</td>
                </tr>
                """,
                    key,
                    value
            ));
        }

        table.append("</table>");
        return table.toString();
    }

    /**
     * Build contact info box
     */
    public String buildContactBox() {
        return String.format("""
            <div style="text-align:center;margin:22px 0;padding:14px;background:#f8f9fa;border-radius:8px;">
                <p style="margin:0;color:#666;font-size:13px;">Need help? Contact us:</p>
                <p style="margin:5px 0 0 0;color:%s;font-size:15px;font-weight:bold;">📞 %s</p>
                %s
            </div>
            """,
                branding.getTheme().getPrimaryColor(),
                branding.getContact().getHotline(),
                branding.getContact().getEmail() != null ?
                        String.format("<p style=\"margin:5px 0 0 0;color:#666;font-size:13px;\">✉️ %s</p>", branding.getContact().getEmail()) :
                        ""
        );
    }

    /**
     * Wrap content in padding
     */
    public String wrapContent(String html) {
        return String.format("""
            <tr>
                <td class="content" style="padding:26px 24px 28px 24px;">
                    %s
                </td>
            </tr>
            """,
                html
        );
    }

    /**
     * Build greeting
     */
    public String buildGreeting(String name) {
        return String.format("""
            <h2 style="color:#333;margin:0 0 10px 0;font-size:22px;">Hello %s,</h2>
            """,
                name != null ? name : "User"
        );
    }

    /**
     * Build paragraph
     */
    public String buildParagraph(String text) {
        return String.format("""
            <p style="font-size:15px;color:#555;margin:0 0 16px 0;">%s</p>
            """,
                text
        );
    }

    public enum AlertType {
        SUCCESS, WARNING, DANGER, INFO
    }

    public enum ButtonStyle {
        PRIMARY, SUCCESS, DANGER, INFO, WARNING
    }
}