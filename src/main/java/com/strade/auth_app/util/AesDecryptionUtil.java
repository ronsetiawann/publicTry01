package com.strade.auth_app.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * AES Decryption Utility - Decrypt password from frontend
 *
 * Algorithm: AES-256-CBC with PKCS7 padding
 * - Key: SHA-256 hash of keyUtf8 (Base64)
 * - IV: MD5 hash of ivUtf8 (Base64)
 */
@Slf4j
public class AesDecryptionUtil {

    /**
     * Decrypt AES encrypted password from frontend
     *
     * @param encBase64 Base64 encrypted string from frontend
     * @param keyUtf8 Key string (will be SHA-256 hashed)
     * @param ivUtf8 IV string (will be MD5 hashed)
     * @return Decrypted plain text password
     */
    public static String decryptAES(String encBase64, String keyUtf8, String ivUtf8) {
        try {
            // Generate key from SHA-256 hash
            String key64 = sha256Hash(keyUtf8);
            byte[] keyBytes = Base64.getDecoder().decode(key64);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            // Generate IV from MD5 hash
            String iv64 = md5Hash(ivUtf8);
            byte[] ivBytes = Base64.getDecoder().decode(iv64);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Setup cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Decrypt
            byte[] encryptedBytes = Base64.getDecoder().decode(encBase64);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("AES decryption failed", e);
            throw new RuntimeException("Failed to decrypt password from frontend", e);
        }
    }

    /**
     * SHA-256 hash and return Base64
     */
    private static String sha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hash failed", e);
        }
    }

    /**
     * MD5 hash and return Base64
     */
    private static String md5Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("MD5 hash failed", e);
        }
    }
}