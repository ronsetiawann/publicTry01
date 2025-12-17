package com.strade.auth_app.service.notification;

import com.strade.auth_app.config.properties.EmailBrandingProperties;
import com.strade.auth_app.config.properties.EmailProperties;
import com.strade.auth_app.entity.NotificationQueue;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.NotificationQueueRepository;
import com.strade.auth_app.security.device.DeviceFingerprint;
import com.strade.auth_app.service.TotpTokenService;
import com.strade.auth_app.service.UserService;
import com.strade.auth_app.util.JsonUtil;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Email service using SMTP with configurable branding
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final EmailProperties emailProperties;
    private final EmailBrandingProperties branding;
    private final EmailTemplateBuilder templateBuilder;
    private final NotificationQueueRepository notificationQueueRepository;
    private final TotpTokenService totpTokenService;
    private final UserService userService;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm:ss");

    //========================================
    // OTP EMAIL
    //========================================

    /**
     * Send OTP via Email with configurable branding
     */
    public String sendOtp(String userId, String email, String name, String otpCode) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending OTP email to {} for user {}", email, userId);

            // 1. Create notification queue entry (PENDING)
            NotificationQueue notification = createNotificationQueue(
                    notificationId, userId, email, name, otpCode
            );
            notificationQueueRepository.save(notification);

            // 2. Prepare email content
            String subject = String.format("Your OTP Code - %s", branding.getApplication().getName());
            String htmlContent = buildOtpEmail(name, otpCode);

            // 3. Send email
            sendEmail(email, subject, htmlContent);

            // 4. Update notification status to SENT
            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("OTP email sent successfully. NotificationId: {}", notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send OTP email for user {}", userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            throw new AuthException(ErrorCode.EMAIL_SEND_FAILED, "Email send failed", e);
        }
    }

    /**
     * Build OTP email using template builder
     */
    private String buildOtpEmail(String name, String otpCode) {
        StringBuilder content = new StringBuilder();

        // Greeting
        content.append(templateBuilder.buildGreeting(name));

        // Introduction
        content.append(templateBuilder.buildParagraph(
                String.format("You have requested to login to your %s account. " +
                                "Please use the following One-Time Password (OTP) to complete your login:",
                        branding.getApplication().getName())
        ));

        // OTP Code Box
        content.append(templateBuilder.buildCodeBox(
                "Your OTP Code",
                otpCode,
                null
        ));

        // Security Info
        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.WARNING,
                "⚠️ Important Security Information:",
                String.format("""
            <ul style="margin:0;padding-left:18px;">
                <li style="margin-bottom:6px;">This OTP is valid for <strong>5 minutes</strong> only</li>
                <li style="margin-bottom:6px;">Do not share this code with anyone, including %s staff</li>
                <li>If you didn't request this OTP, please ignore this email and contact support</li>
            </ul>
            """, branding.getCompany().getShortName())
        ));

        // Contact Box
        content.append(templateBuilder.buildContactBox());

        // Wrap in email template
        return templateBuilder.buildEmail(
                branding.getApplication().getName(),
                branding.getApplication().getTagline(),
                templateBuilder.wrapContent(content.toString())
        );
    }

    //========================================
    // TOTP SETUP EMAIL
    //========================================

    /**
     * Send TOTP setup details via Email
     */
    public String sendTotpSetup(
            String userId,
            String email,
            String name,
            String secret,
            String qrCodeUri,
            List<String> backupCodes,
            boolean includeSecret,
            boolean includeQrUri,
            boolean includeBackupCodes
    ) {
        UUID notificationId = UUID.randomUUID();
        String deliveryMode = emailProperties.getTotp().getDeliveryMode();

        try {
            log.info("Sending TOTP setup email to {} using mode: {}", email, deliveryMode);

            String subject = String.format("TOTP Authentication Setup - %s",
                    branding.getApplication().getName());
            String htmlContent;

            if ("LINK".equalsIgnoreCase(deliveryMode)) {
                UUID token = totpTokenService.createToken(userId, secret, qrCodeUri, backupCodes);
                String setupLink = buildSetupLink(token);
                htmlContent = buildTotpSetupEmailWithLink(name, setupLink);
                log.info("Created TOTP setup token: {}", token);
            } else {
                htmlContent = buildTotpSetupEmailDirect(
                        name, secret, qrCodeUri, backupCodes,
                        includeSecret, includeQrUri, includeBackupCodes
                );
            }

            NotificationQueue notification = createTotpSetupNotificationQueue(
                    notificationId, userId, email, name, deliveryMode
            );
            notificationQueueRepository.save(notification);

            sendEmail(email, subject, htmlContent);

            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("TOTP setup email sent. NotificationId: {}", notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send TOTP setup email for user {}", userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            log.warn("TOTP setup email failed but continuing for user {}", userId);
            return null;
        }
    }

    /**
     * Build TOTP setup email with link
     */
    private String buildTotpSetupEmailWithLink(String name, String setupLink) {
        StringBuilder content = new StringBuilder();
        int expiryMinutes = emailProperties.getTotp().getTokenExpiryMinutes();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("You have successfully initiated TOTP (Time-based One-Time Password) " +
                                "authentication for your %s account. For security reasons, we don't include " +
                                "sensitive setup information directly in this email.",
                        branding.getApplication().getName())
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.INFO,
                "🔗 Access Your Setup Information",
                "Click the button below to securely access your TOTP setup details including " +
                        "QR code, secret key, and backup codes."
        ));

        content.append(templateBuilder.buildButton(
                "📱 Access Setup Information",
                setupLink,
                EmailTemplateBuilder.ButtonStyle.PRIMARY
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.WARNING,
                "⏰ Important Information",
                String.format("""
                <ul style="margin:0;padding-left:20px;">
                    <li style="margin-bottom:8px;">This link is valid for <strong>%d minutes only</strong></li>
                    <li style="margin-bottom:8px;">The link can be accessed <strong>only once</strong></li>
                    <li style="margin-bottom:8px;">After accessing, save your backup codes immediately</li>
                    <li>If the link expires, you'll need to restart the TOTP setup process</li>
                </ul>
                """, expiryMinutes)
        ));

        content.append(templateBuilder.buildInfoBox(
                "📋 What You'll Get",
                """
                <ul style="margin:0;padding-left:20px;">
                    <li style="margin-bottom:8px;"><strong>QR Code:</strong> Scan with your authenticator app</li>
                    <li style="margin-bottom:8px;"><strong>Secret Key:</strong> For manual setup if QR doesn't work</li>
                    <li><strong>Backup Codes:</strong> Use if you lose access to your authenticator</li>
                </ul>
                """
        ));

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                branding.getApplication().getName(),
                "Two-Factor Authentication Setup",
                templateBuilder.wrapContent(content.toString())
        );
    }

    /**
     * Build TOTP setup email direct (with sensitive data)
     */
    private String buildTotpSetupEmailDirect(
            String name, String secret, String qrCodeUri, List<String> backupCodes,
            boolean includeSecret, boolean includeQrUri, boolean includeBackupCodes
    ) {
        StringBuilder content = new StringBuilder();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("You have successfully initiated TOTP authentication for your %s account. " +
                                "This adds an extra layer of security.",
                        branding.getApplication().getName())
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.INFO,
                "📱 Setup Instructions",
                """
                <ol style="margin:10px 0;padding-left:20px;">
                    <li style="margin-bottom:8px;">Download an authenticator app (Google Authenticator, Authy, Microsoft Authenticator)</li>
                    <li style="margin-bottom:8px;">Open the app and scan the QR code below, or manually enter the secret key</li>
                    <li>Enter the 6-digit code from the app to complete activation</li>
                </ol>
                """
        ));

        // QR Code
        if (includeQrUri && qrCodeUri != null) {
            content.append(String.format("""
                <div style="background:white;border:2px solid %s;border-radius:8px;padding:20px;margin:25px 0;text-align:center;">
                    <h3 style="color:%s;margin:0 0 15px 0;font-size:18px;">QR Code for Setup</h3>
                    <p style="color:#666;font-size:14px;margin-bottom:15px;">Scan this with your authenticator app:</p>
                    <div style="background:#f8f9fa;padding:15px;border-radius:5px;margin:10px 0;">
                        <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s" 
                             alt="QR Code" 
                             style="max-width:200px;height:auto;border:2px solid #ddd;border-radius:5px;">
                    </div>
                    <p style="color:#999;font-size:12px;margin-top:10px;">
                        If the image doesn't load, use the manual setup key below
                    </p>
                </div>
                """,
                    branding.getTheme().getPrimaryColor(),
                    branding.getTheme().getPrimaryColor(),
                    qrCodeUri
            ));
        }

        // Secret Key
        if (includeSecret && secret != null) {
            content.append(templateBuilder.buildAlertBox(
                    EmailTemplateBuilder.AlertType.WARNING,
                    "🔑 Manual Setup Key",
                    String.format("""
                    <p style="margin-bottom:10px;">If you can't scan the QR code, enter this key manually:</p>
                    <div style="background:white;border:1px solid %s;border-radius:5px;padding:15px;text-align:center;font-family:'Courier New',monospace;">
                        <code style="color:%s;font-size:18px;letter-spacing:2px;font-weight:bold;word-break:break-all;">%s</code>
                    </div>
                    <p style="margin-top:10px;font-size:12px;">⚠️ Keep this secret safe and never share it with anyone!</p>
                    """,
                            branding.getTheme().getWarningColor(),
                            branding.getTheme().getPrimaryColor(),
                            secret
                    )
            ));
        }

        // Backup Codes
        if (includeBackupCodes && backupCodes != null && !backupCodes.isEmpty()) {
            StringBuilder codes = new StringBuilder();
            codes.append("<div style=\"display:grid;grid-template-columns:repeat(2,1fr);gap:10px;\">");
            for (String code : backupCodes) {
                codes.append(String.format(
                        "<div style=\"background:#f8f9fa;padding:10px;text-align:center;border-radius:4px;" +
                                "font-family:'Courier New',monospace;font-size:14px;color:%s;border:1px solid #bee5eb;" +
                                "font-weight:bold;\">%s</div>",
                        branding.getTheme().getPrimaryColor(),
                        code
                ));
            }
            codes.append("</div>");

            content.append(templateBuilder.buildAlertBox(
                    EmailTemplateBuilder.AlertType.INFO,
                    "💾 Backup Codes",
                    String.format("""
                    <p style="margin-bottom:15px;">
                        Save these backup codes in a secure place. Each code can be used <strong>once</strong> 
                        if you lose access to your authenticator app:
                    </p>
                    <div style="background:white;border:1px solid #0c5460;border-radius:5px;padding:20px;">
                        %s
                    </div>
                    <p style="margin-top:15px;font-size:12px;">
                        ⚠️ Store these codes securely - they won't be shown again!
                    </p>
                    """,
                            codes.toString()
                    )
            ));
        }

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                branding.getApplication().getName(),
                "Two-Factor Authentication Setup",
                templateBuilder.wrapContent(content.toString())
        );
    }

    //========================================
    // UNTRUSTED DEVICE LOGIN EMAIL
    //========================================

    /**
     * Send untrusted device login notification
     */
    public String sendUntrustedDeviceLogin(
            String userId,
            DeviceFingerprint deviceFingerprint,
            String ipAddress
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("📧 Sending untrusted device login email for userId: {}", userId);

            String email = getUserEmail(userId);
            if (email == null || email.isEmpty()) {
                log.warn("User email not found for userId: {}, skipping email", userId);
                return null;
            }
            String userName = getUserName(userId);
            LocalDateTime loginTime = LocalDateTime.now();

            NotificationQueue notification = createUntrustedDeviceNotificationQueue(
                    notificationId, userId, email, userName
            );
            notificationQueueRepository.save(notification);

            String subject = String.format("%s - Login dari Device Baru Terdeteksi",
                    branding.getApplication().getName());
            String htmlContent = buildUntrustedDeviceEmail(
                    userName, userId, deviceFingerprint, ipAddress, loginTime
            );

            sendEmail(email, subject, htmlContent);

            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("✅ Untrusted device email sent. NotificationId: {}", notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("❌ Failed to send untrusted device email for userId: {}", userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            return null;
        }
    }

    /**
     * Build untrusted device login email
     */
    private String buildUntrustedDeviceEmail(
            String name, String userId, DeviceFingerprint device,
            String ipAddress, LocalDateTime loginTime
    ) {
        StringBuilder content = new StringBuilder();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("Kami mendeteksi aktivitas login ke akun %s Anda dari device yang belum " +
                                "terdaftar. Untuk keamanan akun Anda, verifikasi tambahan diperlukan.",
                        branding.getApplication().getName())
        ));

        // Device info box
        String deviceDetails = templateBuilder.buildDetailsTable(
                "User ID", userId,
                "Waktu Login", loginTime.format(DATE_FORMATTER),
                "Tipe Device", formatDeviceType(device.getDeviceType()),
                "Platform", device.getPlatform(),
                "Browser", extractBrowser(device.getUserAgent()),
                "IP Address", ipAddress != null ? ipAddress : "Unknown"
        );

        content.append(String.format("""
            <div style="background:linear-gradient(135deg,#fff5f5 0%%,#ffe0e0 100%%);border-left:4px solid %s;padding:20px;margin:25px 0;border-radius:4px;">
                <p style="margin:0 0 15px 0;color:#333;font-size:14px;font-weight:600;">📱 Device yang Digunakan:</p>
                <p style="margin:0 0 20px 0;padding:12px;background:#ffffff;border-radius:6px;color:%s;font-size:16px;font-weight:600;">%s</p>
                <p style="margin:0 0 12px 0;color:#333;font-size:14px;font-weight:600;">📋 Detail Login:</p>
                %s
            </div>
            """,
                branding.getTheme().getPrimaryColor(),
                branding.getTheme().getPrimaryColor(),
                device.getDeviceName(),
                deviceDetails
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.INFO,
                "✅ Apakah ini Anda?",
                String.format("""
                Jika Anda yang melakukan login ini, silakan lanjutkan proses verifikasi yang muncul di layar Anda. 
                Setelah verifikasi berhasil, device ini akan tersimpan sebagai device terpercaya.<br><br>
                <strong style="color:%s;">⚠️ Jika bukan Anda:</strong> Segera hubungi customer service kami 
                atau ganti password akun Anda untuk keamanan.
                """,
                        branding.getTheme().getDangerColor()
                )
        ));

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                "Login dari Device Baru",
                branding.getApplication().getName(),
                templateBuilder.wrapContent(content.toString())
        );
    }

    //========================================
    // DEVICE SECURITY NOTIFICATIONS
    //========================================

    /**
     * Send device security notification (unified method for ADDED/REMOVED)
     * This method is called from MfaService and DeviceService
     */
    public String sendDeviceSecurityNotification(
            String userId,
            String deviceName,
            String deviceType,
            String platform,
            String action
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending device {} notification for userId: {}", action, userId);

            String email = getUserEmail(userId);
            if (email == null || email.isEmpty()) {
                log.warn("User email not found for userId: {}, skipping email", userId);
                return null;
            }
            String userName = getUserName(userId);
            LocalDateTime actionTime = LocalDateTime.now();

            String subject = String.format("%s - %s",
                    branding.getApplication().getName(),
                    getSubjectByAction(action));

            String htmlContent;
            if ("ADDED".equals(action)) {
                // For ADDED, we need browser and IP which might not be available here
                // So we'll use a simplified version or call the specific method
                htmlContent = buildDeviceAddedEmail(userName, userId, deviceName,
                        deviceType, platform, "Unknown", "Unknown", actionTime);
            } else if ("REMOVED".equals(action)) {
                htmlContent = buildDeviceRemovedEmail(userName, userId, deviceName,
                        deviceType, platform, actionTime);
            } else {
                log.warn("Unknown action type: {}", action);
                return null;
            }

            NotificationQueue notification = createDeviceActionNotificationQueue(
                    notificationId, userId, email, userName, action
            );
            notificationQueueRepository.save(notification);

            sendEmail(email, subject, htmlContent);

            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("Device {} notification sent. NotificationId: {}", action, notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send device {} notification for userId: {}", action, userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            return null;
        }
    }

    /**
     * Send device added notification with full details (including browser and IP)
     * This is the preferred method when all details are available
     */
    public String sendDeviceAddedNotification(
            String userId,
            String deviceName,
            String deviceType,
            String platform,
            String browser,
            String ipAddress
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending device added notification for userId: {}", userId);

            String email = getUserEmail(userId);
            if (email == null) return null;
            String userName = getUserName(userId);
            LocalDateTime addedTime = LocalDateTime.now();

            String subject = String.format("%s - Device Terpercaya Ditambahkan",
                    branding.getApplication().getName());

            String htmlContent = buildDeviceAddedEmail(userName, userId, deviceName,
                    deviceType, platform, browser, ipAddress, addedTime);

            NotificationQueue notification = createDeviceActionNotificationQueue(
                    notificationId, userId, email, userName, "ADDED"
            );
            notificationQueueRepository.save(notification);

            sendEmail(email, subject, htmlContent);

            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("Device added notification sent. NotificationId: {}", notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send device added notification for userId: {}", userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            return null;
        }
    }

    /**
     * Send device replacement notification
     */
    public String sendDeviceReplacementNotification(
            String userId,
            String oldDeviceName,
            String newDeviceName,
            String newDeviceType,
            String platform
    ) {
        UUID notificationId = UUID.randomUUID();

        try {
            log.info("Sending device replacement notification for userId: {}", userId);

            String email = getUserEmail(userId);
            if (email == null || email.isEmpty()) {
                return null;
            }
            String userName = getUserName(userId);
            LocalDateTime actionTime = LocalDateTime.now();

            String subject = String.format("%s - Device Terpercaya Diganti",
                    branding.getApplication().getName());

            String htmlContent = buildDeviceReplacementEmail(userName, userId,
                    oldDeviceName, newDeviceName, newDeviceType, platform, actionTime);

            NotificationQueue notification = createDeviceActionNotificationQueue(
                    notificationId, userId, email, userName, "REPLACED"
            );
            notificationQueueRepository.save(notification);

            sendEmail(email, subject, htmlContent);

            notification.setStatus((byte) 1);
            notification.setSentAt(LocalDateTime.now());
            notificationQueueRepository.save(notification);

            log.info("Device replacement notification sent. NotificationId: {}", notificationId);
            return notificationId.toString();

        } catch (Exception e) {
            log.error("Failed to send device replacement notification for userId: {}", userId, e);
            updateNotificationFailed(notificationId, e.getMessage());
            return null;
        }
    }

    /**
     * Build device added email
     */
    private String buildDeviceAddedEmail(
            String name, String userId, String deviceName, String deviceType,
            String platform, String browser, String ipAddress, LocalDateTime addedTime
    ) {
        StringBuilder content = new StringBuilder();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("Device berikut telah berhasil ditambahkan sebagai device terpercaya untuk " +
                                "akun %s Anda. Anda tidak perlu verifikasi tambahan saat login dari device ini.",
                        branding.getApplication().getName())
        ));

        String details = templateBuilder.buildDetailsTable(
                "User ID", userId,
                "Waktu Ditambahkan", addedTime.format(DATE_FORMATTER),
                "Tipe Device", formatDeviceType(deviceType),
                "Platform", platform,
                "Browser", browser,
                "IP Address", ipAddress
        );

        content.append(String.format("""
            <div style="background:#d4edda;border-left:4px solid %s;padding:20px;margin:25px 0;border-radius:4px;">
                <p style="margin:0 0 15px 0;color:#155724;font-weight:600;">📱 Device Terpercaya:</p>
                <p style="margin:0 0 20px 0;padding:12px;background:#fff;border-radius:6px;color:%s;font-size:16px;font-weight:600;">%s</p>
                <p style="margin:0 0 12px 0;color:#155724;font-weight:600;">📋 Detail Device:</p>
                %s
            </div>
            """,
                branding.getTheme().getSuccessColor(),
                branding.getTheme().getSuccessColor(),
                deviceName,
                details.replace("color:#666", "color:#155724").replace("color:#333", "color:#155724")
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.WARNING,
                "⚠️ Bukan Anda?",
                "Jika Anda tidak menambahkan device ini, segera hubungi customer service atau ganti password akun Anda."
        ));

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                "Device Terpercaya Ditambahkan",
                branding.getApplication().getName(),
                templateBuilder.wrapContent(content.toString())
        );
    }

    /**
     * Build device removed email
     */
    private String buildDeviceRemovedEmail(
            String name, String userId, String deviceName, String deviceType,
            String platform, LocalDateTime removedTime
    ) {
        StringBuilder content = new StringBuilder();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("Device berikut telah dihapus dari daftar device terpercaya untuk akun %s Anda. " +
                                "Anda akan memerlukan verifikasi tambahan saat login dari device ini di masa mendatang.",
                        branding.getApplication().getName())
        ));

        String details = templateBuilder.buildDetailsTable(
                "User ID", userId,
                "Waktu Dihapus", removedTime.format(DATE_FORMATTER),
                "Tipe Device", formatDeviceType(deviceType),
                "Platform", platform
        );

        content.append(String.format("""
            <div style="background:#fff8e1;border-left:4px solid %s;padding:20px;margin:25px 0;border-radius:4px;">
                <p style="margin:0 0 15px 0;color:#f57c00;font-weight:600;">📱 Device yang Dihapus:</p>
                <p style="margin:0 0 20px 0;padding:12px;background:#fff;border-radius:6px;color:%s;font-size:16px;font-weight:600;">%s</p>
                <p style="margin:0 0 12px 0;color:#f57c00;font-weight:600;">📋 Detail Device:</p>
                %s
            </div>
            """,
                branding.getTheme().getWarningColor(),
                branding.getTheme().getWarningColor(),
                deviceName,
                details.replace("color:#666", "color:#f57c00").replace("color:#333", "color:#f57c00")
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.WARNING,
                "⚠️ Bukan Anda?",
                "Jika Anda tidak menghapus device ini, segera hubungi customer service atau ganti password akun Anda untuk keamanan."
        ));

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                "Device Terpercaya Dihapus",
                branding.getApplication().getName(),
                templateBuilder.wrapContent(content.toString())
        );
    }

    /**
     * Build device replacement email
     */
    private String buildDeviceReplacementEmail(
            String name, String userId, String oldDeviceName, String newDeviceName,
            String newDeviceType, String platform, LocalDateTime replacementTime
    ) {
        StringBuilder content = new StringBuilder();

        content.append(templateBuilder.buildGreeting(name));

        content.append(templateBuilder.buildParagraph(
                String.format("Anda telah berhasil mengganti device terpercaya untuk akun %s Anda.",
                        branding.getApplication().getName())
        ));

        String details = templateBuilder.buildDetailsTable(
                "User ID", userId,
                "Waktu Penggantian", replacementTime.format(DATE_FORMATTER),
                "Tipe Device", formatDeviceType(newDeviceType),
                "Platform", platform
        );

        content.append(String.format("""
            <div style="background:#d1ecf1;border-left:4px solid %s;padding:20px;margin:25px 0;border-radius:4px;">
                <p style="margin:0 0 12px 0;color:#0c5460;font-weight:600;">📱 Device Lama (Dihapus):</p>
                <p style="margin:0 0 15px 0;padding:10px;background:#fff;border-radius:6px;color:#dc3545;font-size:15px;font-weight:500;text-decoration:line-through;">%s</p>
                
                <p style="margin:15px 0 12px 0;color:#0c5460;font-weight:600;">📱 Device Baru (Ditambahkan):</p>
                <p style="margin:0 0 20px 0;padding:10px;background:#fff;border-radius:6px;color:#28a745;font-size:16px;font-weight:600;">%s</p>
                
                <p style="margin:0 0 12px 0;color:#0c5460;font-weight:600;">📋 Detail Device:</p>
                %s
            </div>
            """,
                branding.getTheme().getInfoColor(),
                oldDeviceName,
                newDeviceName,
                details.replace("color:#666", "color:#0c5460").replace("color:#333", "color:#0c5460")
        ));

        content.append(templateBuilder.buildAlertBox(
                EmailTemplateBuilder.AlertType.WARNING,
                "⚠️ Bukan Anda?",
                "Jika Anda tidak melakukan penggantian device ini, segera hubungi customer service."
        ));

        content.append(templateBuilder.buildContactBox());

        return templateBuilder.buildEmail(
                "Device Terpercaya Diganti",
                branding.getApplication().getName(),
                templateBuilder.wrapContent(content.toString())
        );
    }

    //========================================
    // HELPER METHODS
    //========================================

    /**
     * Send email using JavaMailSender
     */
    private void sendEmail(String to, String subject, String htmlContent)
            throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(emailProperties.getFrom(), emailProperties.getFromName());
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }

    /**
     * Create notification queue entry for OTP
     */
    private NotificationQueue createNotificationQueue(
            UUID notificationId, String userId, String email, String name, String otpCode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("email", email);
        templateData.put("name", name);
        templateData.put("otp_code", otpCode);

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("OTP_LOGIN_2FA")
                .channel("email")
                .destination(email)
                .subject("Your OTP Code")
                .body("Your OTP code is: " + otpCode)
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Create notification queue entry for TOTP setup
     */
    private NotificationQueue createTotpSetupNotificationQueue(
            UUID notificationId, String userId, String email, String name, String deliveryMode
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("email", email);
        templateData.put("name", name);
        templateData.put("delivery_mode", deliveryMode);

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("TOTP_SETUP")
                .channel("email")
                .destination(email)
                .subject("TOTP Authentication Setup")
                .body("TOTP setup details")
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Create notification queue entry for untrusted device login
     */
    private NotificationQueue createUntrustedDeviceNotificationQueue(
            UUID notificationId, String userId, String email, String userName
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("email", email);
        templateData.put("name", userName);

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("UNTRUSTED_DEVICE_LOGIN")
                .channel("email")
                .destination(email)
                .subject("Login from untrusted device")
                .body("Untrusted device login detected")
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Create notification queue entry for device actions
     */
    private NotificationQueue createDeviceActionNotificationQueue(
            UUID notificationId, String userId, String email, String userName, String action
    ) {
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("email", email);
        templateData.put("name", userName);
        templateData.put("action", action);

        return NotificationQueue.builder()
                .notificationId(notificationId)
                .userId(userId)
                .type("DEVICE_" + action)
                .channel("email")
                .destination(email)
                .subject("Device notification")
                .body("Device " + action.toLowerCase())
                .templateData(JsonUtil.toJson(templateData))
                .status((byte) 0)
                .retryCount((byte) 0)
                .createdAt(LocalDateTime.now())
                .build();
    }

    /**
     * Update notification status to FAILED
     */
    private void updateNotificationFailed(UUID notificationId, String errorMessage) {
        notificationQueueRepository.findById(notificationId).ifPresent(notif -> {
            notif.setStatus((byte) 2);
            notif.setErrorMessage(errorMessage);
            notif.setRetryCount((byte) (notif.getRetryCount() + 1));
            notificationQueueRepository.save(notif);
        });
    }

    /**
     * Build setup link with token
     */
    private String buildSetupLink(UUID token) {
        String baseUrl = emailProperties.getTotp().getSetupBaseUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            baseUrl = "http://10.192.7.10:8098/totp-setup";
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + "/" + token.toString();
    }

    /**
     * Get user email using UserService
     */
    private String getUserEmail(String userId) {
        try {
            return userService.getUserEmailFromContact(userId);
        } catch (Exception e) {
            log.warn("Failed to get email for userId: {}", userId);
            return null;
        }
    }

    /**
     * Get username using UserService
     */
    private String getUserName(String userId) {
        try {
            return userService.getUserNameFromContact(userId);
        } catch (Exception e) {
            log.warn("Failed to get name for userId: {}, using 'User'", userId);
            return "User";
        }
    }

    /**
     * Format device type to user-friendly text
     */
    private String formatDeviceType(String deviceType) {
        if (deviceType == null || deviceType.isEmpty()) {
            return "Unknown Device";
        }
        return switch (deviceType.toLowerCase()) {
            case "mobile" -> "Mobile Phone";
            case "tablet" -> "Tablet";
            case "desktop" -> "Desktop Computer";
            case "web" -> "Web Browser";
            default -> deviceType;
        };
    }

    /**
     * Extract browser name from user agent
     */
    private String extractBrowser(String userAgent) {
        if (userAgent == null || userAgent.isEmpty() || "Unknown".equals(userAgent)) {
            return "Unknown Browser";
        }
        String lower = userAgent.toLowerCase();
        if (lower.contains("edg/")) return "Microsoft Edge";
        if (lower.contains("chrome/")) return "Google Chrome";
        if (lower.contains("firefox/")) return "Mozilla Firefox";
        if (lower.contains("safari/") && !lower.contains("chrome")) return "Safari";
        if (lower.contains("opera/") || lower.contains("opr/")) return "Opera";
        return "Unknown Browser";
    }

    /**
     * Get subject text based on action type
     */
    private String getSubjectByAction(String action) {
        return switch (action) {
            case "ADDED" -> "Device Terpercaya Berhasil Ditambahkan";
            case "REMOVED" -> "Device Terpercaya Telah Dihapus";
            case "REPLACED" -> "Device Terpercaya Diganti";
            default -> "Notifikasi Device Terpercaya";
        };
    }
}