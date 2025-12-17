package com.strade.auth_app.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Year;

/**
 * Branding & theme configuration for email templates.
 * Source: app.mail.branding.* in application.yml
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app.mail.branding")
public class EmailBrandingProperties {

    private Company company = new Company();
    private Application application = new Application();
    private Contact contact = new Contact();
    private Theme theme = new Theme();
    private Footer footer = new Footer();

    // ====== Convenience methods for gradients ======

    /**
     * Header gradient, fallback ke primaryColor kalau gradient tidak didefinisikan.
     */
    public String getHeaderGradient() {
        if (theme.getGradientStart() != null && theme.getGradientEnd() != null) {
            return String.format(
                    "linear-gradient(135deg,%s 0%%,%s 100%%)",
                    theme.getGradientStart(),
                    theme.getGradientEnd()
            );
        }
        // fallback: pakai primaryColor saja
        return theme.getPrimaryColor() != null ? theme.getPrimaryColor() : "#DC143C";
    }

    public String getSuccessGradient() {
        String color = theme.getSuccessColor() != null ? theme.getSuccessColor() : "#28a745";
        return String.format("linear-gradient(135deg,%s 0%%,%s 100%%)", color, color);
    }

    public String getDangerGradient() {
        String color = theme.getDangerColor() != null ? theme.getDangerColor() : "#dc3545";
        return String.format("linear-gradient(135deg,%s 0%%,%s 100%%)", color, color);
    }

    public String getInfoGradient() {
        String color = theme.getInfoColor() != null ? theme.getInfoColor() : "#17a2b8";
        return String.format("linear-gradient(135deg,%s 0%%,%s 100%%)", color, color);
    }

    public String getWarningGradient() {
        String color = theme.getWarningColor() != null ? theme.getWarningColor() : "#ffc107";
        return String.format("linear-gradient(135deg,%s 0%%,%s 100%%)", color, color);
    }

    // ====== Nested classes mapping ke YAML ======

    @Getter
    @Setter
    public static class Company {
        // app.mail.branding.company.name
        private String name;

        // app.mail.branding.company.short-name
        private String shortName;

        // app.mail.branding.company.description
        private String description;
    }

    @Getter
    @Setter
    public static class Application {
        // app.mail.branding.application.name
        private String name;

        // app.mail.branding.application.tagline
        private String tagline;

        // app.mail.branding.application.url
        private String url;
    }

    @Getter
    @Setter
    public static class Contact {
        // app.mail.branding.contact.hotline
        private String hotline;

        // app.mail.branding.contact.email
        private String email;

        // app.mail.branding.contact.hours
        private String hours;

        // app.mail.branding.contact.support-url
        private String supportUrl;
    }

    @Getter
    @Setter
    public static class Theme {
        // app.mail.branding.theme.primary-color
        private String primaryColor;

        // app.mail.branding.theme.secondary-color
        private String secondaryColor;

        // app.mail.branding.theme.success-color
        private String successColor;

        // app.mail.branding.theme.warning-color
        private String warningColor;

        // app.mail.branding.theme.danger-color
        private String dangerColor;

        // app.mail.branding.theme.info-color
        private String infoColor;

        // app.mail.branding.theme.primary-text-color
        private String primaryTextColor;

        // app.mail.branding.theme.gradient-start
        private String gradientStart;

        // app.mail.branding.theme.gradient-end
        private String gradientEnd;
    }

    @Getter
    @Setter
    public static class Footer {
        // app.mail.branding.footer.copyright-year
        private Integer copyrightYear;

        // app.mail.branding.footer.copyright-text
        // e.g. "© {year} {company}. All rights reserved."
        private String copyrightText;

        // app.mail.branding.footer.show-do-not-reply
        private boolean showDoNotReply = true;

        // app.mail.branding.footer.do-not-reply-text
        private String doNotReplyText;

        // app.mail.branding.footer.additional-text
        private String additionalText;

        /**
         * Build final copyright text dengan replace {year} dan {company}.
         * Di EmailTemplateBuilder sekarang dipanggil dengan:
         *   getFullCopyrightText(branding.getApplication().getName())
         */
        public String getFullCopyrightText(String companyOrAppName) {
            int year = (copyrightYear != null)
                    ? copyrightYear
                    : Year.now().getValue();

            String template = (copyrightText != null && !copyrightText.isBlank())
                    ? copyrightText
                    : "© {year} {company}. All rights reserved.";

            return template
                    .replace("{year}", String.valueOf(year))
                    .replace("{company}", companyOrAppName != null ? companyOrAppName : "");
        }
    }
}
