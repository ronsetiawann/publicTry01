package com.strade.auth_app.service;

import com.strade.auth_app.config.properties.AppProperties;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinCrypt;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordHashService {

    private final RestTemplate restTemplate;
    private final RedisTemplate<String, String> redisTemplate;
    private final AppProperties appProperties;

    // Windows Crypto API Constants
    private static final int PROV_RSA_FULL = 1;
    private static final int CRYPT_VERIFYCONTEXT = 0xF0000000;
    private static final int CALG_MD5 = 0x00008003;
    private static final int CALG_3DES = 0x00006603;
    private static final int HP_HASHVAL = 0x0002;
    private static final int HP_HASHSIZE = 0x0004;
    private static final byte[] IV = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};

    // JNA Interface for Windows Crypto API
    public interface Advapi32Ext extends StdCallLibrary {
        Advapi32Ext INSTANCE = Native.load("Advapi32", Advapi32Ext.class);

        boolean CryptAcquireContextW(
                PointerByReference phProv,
                String pszContainer,
                String pszProvider,
                int dwProvType,
                int dwFlags
        );

        boolean CryptCreateHash(
                Pointer hProv,
                int Algid,
                Pointer hKey,
                int dwFlags,
                PointerByReference phHash
        );

        boolean CryptHashData(
                Pointer hHash,
                byte[] pbData,
                int dwDataLen,
                int dwFlags
        );

        boolean CryptDeriveKey(
                Pointer hProv,
                int Algid,
                Pointer hBaseData,
                int dwFlags,
                PointerByReference phKey
        );

        boolean CryptGetHashParam(
                Pointer hHash,
                int dwParam,
                byte[] pbData,
                IntByReference pdwDataLen,
                int dwFlags
        );

        boolean CryptEncrypt(
                Pointer hKey,
                Pointer hHash,
                boolean Final,
                int dwFlags,
                byte[] pbData,
                IntByReference pdwDataLen,
                int dwBufLen
        );

        boolean CryptDestroyHash(Pointer hHash);
        boolean CryptDestroyKey(Pointer hKey);
        boolean CryptReleaseContext(Pointer hProv, int dwFlags);
    }

    public String hashPassword(String password) {
        AppProperties.PasswordProperties.HashStrategy strategy =
                appProperties.getPassword().getHashStrategy();

        switch (strategy) {
            case JNA:
                return hashPasswordWithJNA(password);

            case ENDPOINT:
                return hashPasswordWithEndpoint(password);

            case AUTO:
            default:
                if (isJNAAvailable()) {
                    try {
                        return hashPasswordWithJNA(password);
                    } catch (Exception e) {
                        log.warn("JNA hashing failed, falling back to endpoint", e);
                        return hashPasswordWithEndpoint(password);
                    }
                } else {
                    return hashPasswordWithEndpoint(password);
                }
        }
    }

    /**
     * Hash password using Windows CryptoAPI via JNA
     * Mimics C# PasswordDeriveBytes.CryptDeriveKey exactly
     */
    private String hashPasswordWithJNA(String password) {
        if (!isJNAAvailable()) {
            throw new UnsupportedOperationException(
                    "JNA Windows CryptoAPI only available on Windows. Current OS: "
                            + System.getProperty("os.name")
            );
        }

        PointerByReference hProv = new PointerByReference();
        PointerByReference hHash = new PointerByReference();
        PointerByReference hKey = new PointerByReference();

        try {
            log.debug("Starting JNA Windows CryptoAPI password hashing");

            // Step 1: Acquire crypto context
            if (!Advapi32Ext.INSTANCE.CryptAcquireContextW(
                    hProv, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                throw new RuntimeException("CryptAcquireContext failed");
            }

            // Step 2: Prepare data (add tail + UTF-16LE)
            String dataToEncrypt = password + "\u0008";
            byte[] dataBytes = dataToEncrypt.getBytes(StandardCharsets.UTF_16LE);
            byte[] keyBytes = password.getBytes(StandardCharsets.UTF_16LE);

            // Step 3: Create hash object for password
            if (!Advapi32Ext.INSTANCE.CryptCreateHash(
                    hProv.getValue(), CALG_MD5, Pointer.NULL, 0, hHash)) {
                throw new RuntimeException("CryptCreateHash failed");
            }

            // Step 4: Hash the password bytes
            if (!Advapi32Ext.INSTANCE.CryptHashData(
                    hHash.getValue(), keyBytes, keyBytes.length, 0)) {
                throw new RuntimeException("CryptHashData failed");
            }

            // Step 5: Derive 3DES key from hash
            if (!Advapi32Ext.INSTANCE.CryptDeriveKey(
                    hProv.getValue(), CALG_3DES, hHash.getValue(), 0, hKey)) {
                throw new RuntimeException("CryptDeriveKey failed");
            }

            // Step 6: Encrypt data with derived key
            byte[] encryptedData = new byte[dataBytes.length + 8]; // Extra space for padding
            System.arraycopy(dataBytes, 0, encryptedData, 0, dataBytes.length);
            IntByReference dataLen = new IntByReference(dataBytes.length);

            if (!Advapi32Ext.INSTANCE.CryptEncrypt(
                    hKey.getValue(), Pointer.NULL, true, 0,
                    encryptedData, dataLen, encryptedData.length)) {
                throw new RuntimeException("CryptEncrypt failed");
            }

            // Trim to actual encrypted size
            byte[] encrypted = new byte[dataLen.getValue()];
            System.arraycopy(encryptedData, 0, encrypted, 0, encrypted.length);

            // Step 7: Convert through ANSI encoding
            Charset ansiCharset = getAnsiCharset();
            String tempStr = new String(encrypted, ansiCharset);
            byte[] preHashBytes = tempStr.getBytes(StandardCharsets.UTF_16LE);

            // Step 8: MD5 hash
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md5.digest(preHashBytes);

            // Step 9: Convert to hex string
            String result = bytesToHex(hashBytes).toUpperCase();

            log.debug("JNA password hashing successful: {} chars", result.length());
            return result;

        } catch (Exception e) {
            log.error("JNA password hashing failed", e);
            throw new RuntimeException("Windows CryptoAPI hashing failed", e);
        } finally {
            // Cleanup
            if (hKey.getValue() != null && hKey.getValue() != Pointer.NULL) {
                Advapi32Ext.INSTANCE.CryptDestroyKey(hKey.getValue());
            }
            if (hHash.getValue() != null && hHash.getValue() != Pointer.NULL) {
                Advapi32Ext.INSTANCE.CryptDestroyHash(hHash.getValue());
            }
            if (hProv.getValue() != null && hProv.getValue() != Pointer.NULL) {
                Advapi32Ext.INSTANCE.CryptReleaseContext(hProv.getValue(), 0);
            }
        }
    }

    private String hashPasswordWithEndpoint(String password) {
        String cacheKey = "password:hash:" + password;
        String cachedHash = redisTemplate.opsForValue().get(cacheKey);

        if (cachedHash != null) {
            log.debug("Password hash retrieved from cache");
            return cachedHash;
        }

        try {
            String url = UriComponentsBuilder
                    .fromHttpUrl(appProperties.getPassword().getHashEndpointUrl())
                    .queryParam("q", password)
                    .toUriString();

            log.debug("Calling C# hash endpoint");

            String hash = restTemplate.getForObject(url, String.class);

            if (hash == null || hash.isEmpty()) {
                throw new RuntimeException("Empty hash response from C# endpoint");
            }

            if (!hash.matches("[A-F0-9]{32}")) {
                throw new RuntimeException("Invalid hash format: " + hash);
            }

            redisTemplate.opsForValue().set(cacheKey, hash, 24, TimeUnit.HOURS);

            log.debug("Password hashed via C# endpoint and cached");
            return hash;

        } catch (Exception e) {
            log.error("Failed to hash password via C# endpoint", e);
            throw new RuntimeException("Password hashing via endpoint failed", e);
        }
    }

    private boolean isJNAAvailable() {
        return Platform.isWindows();
    }

    private Charset getAnsiCharset() {
        try {
            return Charset.forName("Cp1252");
        } catch (Exception e) {
            try {
                return Charset.forName("Windows-1252");
            } catch (Exception e2) {
                return Charset.forName("ISO-8859-1");
            }
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}