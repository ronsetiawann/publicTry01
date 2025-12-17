package com.strade.auth_app.util;

import com.strade.auth_app.service.PasswordHashService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Password encryption utility - LEGACY C# COMPATIBILITY
 *
 * Features:
 * 1. TripleDES + MD5 encryption for DB storage (C# bcEncrypt/EncryptHash)
 * 2. Simple char substitution (C# SEncrypt/SDecrypt)
 * 3. AES decryption for frontend passwords [ENC0...]
 */
@Slf4j
public class PasswordEncryptionUtil {

    private static final byte[] IV = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Decrypt mode for frontend passwords
     */
    public enum DecryptMode {
        WEB,
        MOBILE
    }

    // ==================== DB STORAGE METHODS ====================

    /**
     * Advanced encrypt (mimics C# bcEncrypt) - TripleDES + MD5
     * Example: "abc123" → "C42ACE1A5316FC7A85CA2F38C51FF561"
     *
     * @param password Plain text password
     * @param key Encryption key (usually same as password)
     * @return 32-character uppercase hex string
     */
    public static String encryptHash(String password, String key) {
        return encryptHash(password, key, true);
    }

    /**
     * Hash password using external service (for TripleDES+MD5)
     */
    public static String encryptHashViaService(String password, PasswordHashService hashService) {
        return hashService.hashPassword(password);
    }

    /**
     * Advanced encrypt with options
     *
     * @param password Plain text password
     * @param key Encryption key
     * @param addTail Whether to append \x08 tail
     * @return 32-character uppercase hex string
     */
    public static String encryptHash(String password, String key, boolean addTail) {
        try {
            // Step 1: Add tail if needed
            String dataToEncrypt = addTail ? password + "\u0008" : password;

            // Step 2: Convert to Unicode (UTF-16LE) bytes
            byte[] dataBytes = dataToEncrypt.getBytes(StandardCharsets.UTF_16LE);
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_16LE);

            // Step 3: Derive TripleDES key
            byte[] derivedKey = deriveTripleDESKey(keyBytes);

            // Step 4: TripleDES encryption
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            KeySpec keySpec = new DESedeKeySpec(derivedKey);
            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encrypted = cipher.doFinal(dataBytes);

            // Step 5: Convert through ANSI encoding (Windows-1252 or ISO-8859-1)
            Charset ansiCharset = getAnsiCharset();
            String tempStr = new String(encrypted, ansiCharset);
            byte[] preHashBytes = tempStr.getBytes(StandardCharsets.UTF_16LE);

            // Step 6: MD5 hash
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md5.digest(preHashBytes);

            // Step 7: Convert to uppercase hex string
            return bytesToHex(hashBytes).toUpperCase();

        } catch (Exception e) {
            log.error("Error encrypting password", e);
            throw new RuntimeException("Password encryption failed", e);
        }
    }

    /**
     * Simple encrypt (mimics C# SEncrypt)
     * Example: "123456" → "ÙÛÝßáã"
     */
    public static String simpleEncrypt(String source) {
        if (source == null || source.isEmpty()) {
            return source;
        }

        StringBuilder dest = new StringBuilder();
        int length = source.length();

        for (int i = 1; i <= length; i++) {
            char c = (char) (270 + i - (int) source.charAt(length - i));
            dest.append(c);
        }

        return dest.toString();
    }

    /**
     * Simple decrypt (mimics C# SDecrypt)
     */
    public static String simpleDecrypt(String source) {
        if (source == null || source.isEmpty()) {
            return source;
        }

        StringBuilder dest = new StringBuilder();
        int length = source.length();

        for (int i = 1; i <= length; i++) {
            char c = (char) (270 + i - (int) source.charAt(i - 1));
            dest.insert(0, c);
        }

        return dest.toString();
    }

    // ==================== FRONTEND DECRYPTION ====================

    /**
     * Decrypt password dari frontend format [ENC0...]
     * Supports both Web (C#) and Mobile (Dart) encryption formats
     *
     * @param encryptedPassword Password terenkripsi dari frontend
     * @param mode Mode decrypt (WEB atau MOBILE)
     * @return Password plaintext
     */
    public static String decryptFromFrontend(String encryptedPassword, DecryptMode mode) {
        if (encryptedPassword == null || encryptedPassword.isEmpty()) {
            return "";
        }

        // Jika bukan format encrypted, return as-is (backward compatibility)
        if (!encryptedPassword.startsWith("[ENC0") || !encryptedPassword.endsWith("]")) {
            log.debug("Password not in [ENC0...] format, returning as-is");
            return encryptedPassword;
        }

        try {
            // Extract content between [ENC0 and ]
            String content = encryptedPassword.substring(5, encryptedPassword.length() - 1);

            int indexZ = content.indexOf('Z');
            if (indexZ <= 0) {
                log.warn("Invalid [ENC0...] format: missing 'Z' separator");
                return encryptedPassword;
            }

            int indexA = content.indexOf('a', indexZ);
            if (indexA <= indexZ) {
                log.warn("Invalid [ENC0...] format: missing 'a' separator");
                return encryptedPassword;
            }

            // Parse components
            String key = content.substring(0, indexZ);
            int originalLength = Integer.parseInt(content.substring(indexZ + 1, indexA));
            String encryptedMessage = content.substring(indexA + 1);

            log.debug("Decrypting frontend password: key={}, originalLength={}, mode={}",
                    key, originalLength, mode);

            // Replace URL-safe characters back to Base64 standard
            encryptedMessage = encryptedMessage.replace('-', '/').replace('_', '+');

            // Add padding if needed
            while (encryptedMessage.length() % 4 != 0) {
                encryptedMessage += "=";
            }

            // Decrypt based on mode
            String decrypted;
            if (mode == DecryptMode.WEB) {
                decrypted = aesDecryptWeb(encryptedMessage, key, key + key);
            } else {
                decrypted = aesDecryptMobile(encryptedMessage, key, key + key);
            }

            // Get substring according to original length
            int endIndex = Math.min(originalLength, decrypted.length());
            String result = decrypted.substring(0, endIndex);

            log.debug("Frontend password decrypted successfully: {} chars", result.length());
            return result;

        } catch (Exception e) {
            log.error("Failed to decrypt frontend password", e);
            throw new RuntimeException("Frontend password decryption failed", e);
        }
    }

    /**
     * AES Decrypt - WEB Mode (C# style)
     * Output: Direct plaintext string (FIXED - no base64 decode)
     */
    private static String aesDecryptWeb(String cipherText, String key, String iv) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
            byte[] keyBytes = sha256Hash(key);
            byte[] ivBytes = md5HashBytes(iv);

            AESEngine engine = new AESEngine();
            CBCBlockCipher blockCipher = new CBCBlockCipher(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);

            KeyParameter keyParam = new KeyParameter(keyBytes);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, ivBytes, 0, ivBytes.length);

            cipher.init(false, keyParamWithIV);

            byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            int length = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
            int finalLength = cipher.doFinal(decryptedBytes, length);

            // FIX: Return plaintext directly (same as mobile)
            byte[] result = new byte[length + finalLength];
            System.arraycopy(decryptedBytes, 0, result, 0, result.length);
            return new String(result, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("AES decryption failed (WEB mode)", e);
        }
    }



    /**
     * AES Decrypt - MOBILE Mode (Dart style)
     * Output: Direct plaintext string
     */
    private static String aesDecryptMobile(String cipherText, String key, String iv) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
            byte[] keyBytes = sha256Hash(key);
            byte[] ivBytes = md5HashBytes(iv);

            AESEngine engine = new AESEngine();
            CBCBlockCipher blockCipher = new CBCBlockCipher(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher);

            KeyParameter keyParam = new KeyParameter(keyBytes);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, ivBytes, 0, ivBytes.length);

            cipher.init(false, keyParamWithIV);

            byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            int length = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
            int finalLength = cipher.doFinal(decryptedBytes, length);

            // Return as plaintext string (Dart style - direct output)
            byte[] result = new byte[length + finalLength];
            System.arraycopy(decryptedBytes, 0, result, 0, result.length);
            return new String(result, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("AES decryption failed (MOBILE mode)", e);
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Derive TripleDES key from password bytes
     * Mimics C# PasswordDeriveBytes.CryptDeriveKey("TripleDES", "MD5", 192, IV)
     */
    private static byte[] deriveTripleDESKey(byte[] passwordBytes) throws Exception {
        // TripleDES requires 192-bit (24 bytes) key
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash1 = md5.digest(passwordBytes);

        // For 192-bit key, we need 24 bytes
        byte[] temp = new byte[passwordBytes.length + IV.length];
        System.arraycopy(passwordBytes, 0, temp, 0, passwordBytes.length);
        System.arraycopy(IV, 0, temp, passwordBytes.length, IV.length);
        byte[] hash2 = md5.digest(temp);

        // Combine: first 16 bytes from hash1, next 8 bytes from hash2
        byte[] key24 = new byte[24];
        System.arraycopy(hash1, 0, key24, 0, 16);
        System.arraycopy(hash2, 0, key24, 16, 8);

        return key24;
    }

    /**
     * Get ANSI charset (Windows-1252 or fallback to ISO-8859-1)
     */
    private static Charset getAnsiCharset() {
        // Priority list of charsets to try
        String[] charsetNames = {
                "Cp1252",        // Windows Codepage 1252 (most common)
                "Windows-1252",  // Alternative name
                "ISO-8859-1",    // Latin-1 (fallback)
                "US-ASCII"       // Final fallback
        };

        for (String charsetName : charsetNames) {
            try {
                Charset charset = Charset.forName(charsetName);
                log.debug("Using charset: {}", charsetName);
                return charset;
            } catch (Exception e) {
                log.debug("Charset {} not available", charsetName);
            }
        }

        // Ultimate fallback
        log.warn("No preferred charset available, using default");
        return Charset.defaultCharset();
    }

    /**
     * SHA-256 hash for AES key derivation
     */
    private static byte[] sha256Hash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hash failed", e);
        }
    }

    /**
     * MD5 hash for AES IV derivation
     */
    private static byte[] md5HashBytes(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("MD5 hash failed", e);
        }
    }

    /**
     * Convert bytes to hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}