package com.strade.auth_app.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@TestPropertySource(properties = {
        "app.password.hash-strategy=JNA"  // AUTO: Try JNA on Windows, fallback to ENDPOINT
})
class PasswordHashServiceTest {

    @Autowired
    private PasswordHashService passwordHashService;

    @Test
    void testHashPassword() {
        String password = "abc123";
        String expected = "C42ACE1A5316FC7A85CA2F38C51FF561";

        String hash = passwordHashService.hashPassword(password);

        System.out.println("=================================");
        System.out.println("Password Hash Test");
        System.out.println("=================================");
        System.out.println("OS:       " + System.getProperty("os.name"));
        System.out.println("Password: " + password);
        System.out.println("Hash:     " + hash);
        System.out.println("Expected: " + expected);
        System.out.println("Match:    " + (hash.equals(expected) ? "✅ YES" : "❌ NO"));
        System.out.println("=================================");

        // Validate format
        assertNotNull(hash);
        assertEquals(32, hash.length());
        assertTrue(hash.matches("[A-F0-9]{32}"));

        // Validate against C# result
        assertEquals(expected, hash, "Hash should match C# implementation");
    }

    @Test
    void testHashPasswordMultiple() {
        // Test multiple passwords
        String[][] testCases = {
                {"abc123", "C42ACE1A5316FC7A85CA2F38C51FF561"},
                {"test", "098F6BCD4621D373CADE4E832627B4F6"},  // Replace with actual C# hash
                {"password", "5F4DCC3B5AA765D61D8327DEB882CF99"}  // Replace with actual C# hash
        };

        for (String[] testCase : testCases) {
            String password = testCase[0];
            String hash = passwordHashService.hashPassword(password);

            System.out.println("Password: " + password + " -> Hash: " + hash);

            assertNotNull(hash);
            assertEquals(32, hash.length());
            assertTrue(hash.matches("[A-F0-9]{32}"));
        }
    }
}
