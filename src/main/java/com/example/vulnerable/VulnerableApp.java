package com.example.vulnerable;

import com.example.moredeadcode.DeadCodeProvider1;
import com.example.moredeadcode.DeadCodeProvider2;

public class VulnerableApp {

    // NON-DEAD CODE: This method will be called from Main.java
    public static void runVulnerableOperations() {
        System.out.println("Running vulnerable operations in VulnerableApp...");
        
        // Call methods from other modules - making them NOT dead
        String userInput = "test_input_123";
        boolean isValid = DeadCodeProvider1.validateInput(userInput);
        System.out.println("Input validation result: " + isValid);
        
        if (isValid) {
            String formatted = DeadCodeProvider2.formatMessage(userInput);
            System.out.println("Formatted message: " + formatted);
        }
        
        // Call internal method
        processUnsafeData("../../../etc/passwd");
        
        // VULNERABILITY: Call database vulnerabilities
        testDatabaseVulnerabilities();
          // VULNERABILITY: Call web vulnerabilities  
        testWebVulnerabilities();
        
        // VULNERABILITY: Call crypto vulnerabilities
        testCryptoVulnerabilities();
    }

    // NON-DEAD CODE: Called by runVulnerableOperations
    private static void testDatabaseVulnerabilities() {
        System.out.println("\n=== Testing Database Vulnerabilities ===");
        
        // VULNERABLE: SQL injection through user lookup
        String result1 = DatabaseVulnerabilities.vulnerableUserLookup("admin' OR '1'='1");
        System.out.println("Vulnerable lookup result: " + result1);
        
        // VULNERABLE: SQL injection in search
        String result2 = DatabaseVulnerabilities.searchUsers("test", "id; DROP TABLE users--");
        System.out.println("Search result: " + result2);
        
        // VULNERABLE: Update with injection
        DatabaseVulnerabilities.updateUserRole("user1'; DROP TABLE logs; --", "admin");
        
        // VULNERABLE: Login with credential exposure
        String loginResult = DatabaseVulnerabilities.loginUser("admin", "password123");
        System.out.println("Login result: " + loginResult);
        
        System.out.println("=== Database Vulnerabilities Test Complete ===\n");
    }

    // NON-DEAD CODE: Called by runVulnerableOperations
    private static void testWebVulnerabilities() {
        System.out.println("\n=== Testing Web Vulnerabilities ===");
        
        // VULNERABLE: XSS in user profile
        String profile = WebVulnerabilities.generateUserProfile(
            "<script>alert('XSS')</script>", 
            "<img src=x onerror=alert('XSS')>"
        );
        System.out.println("Generated profile with XSS: " + profile.length() + " chars");
        
        // VULNERABLE: SSRF attempt
        String ssrfResult = WebVulnerabilities.fetchExternalData("http://169.254.169.254/metadata");
        System.out.println("SSRF result length: " + ssrfResult.length());
        
        // VULNERABLE: Weak encryption
        String weakHash = WebVulnerabilities.weakEncryption("sensitive_password");
        System.out.println("Weak hash: " + weakHash);
        
        // VULNERABLE: Hardcoded credentials usage
        String serviceConnection = WebVulnerabilities.connectToService();
        System.out.println("Service connection: " + serviceConnection);
        
        // VULNERABLE: Information disclosure in logs
        WebVulnerabilities.processLogin("admin", "secret123", "tok_abc123def456");
        
        // VULNERABLE: Directory traversal
        String configContent = WebVulnerabilities.readConfigFile("../../../etc/passwd");
        System.out.println("Config read attempt result length: " + configContent.length());
        
        // VULNERABLE: Race condition
        for (int i = 0; i < 3; i++) {
            String counterResult = WebVulnerabilities.incrementCounter("user" + i);
            System.out.println("Counter: " + counterResult);
        }
        
        // VULNERABLE: Input validation issues
        String ageResult1 = WebVulnerabilities.processAge("25");
        String ageResult2 = WebVulnerabilities.processAge("invalid_age");
        String ageResult3 = WebVulnerabilities.processAge("-5");        System.out.println("Age results: " + ageResult1 + ", " + ageResult2 + ", " + ageResult3);
        
        System.out.println("=== Web Vulnerabilities Test Complete ===\n");
    }

    // NON-DEAD CODE: Called by runVulnerableOperations
    private static void testCryptoVulnerabilities() {
        System.out.println("\n=== Testing Crypto Vulnerabilities ===");
        
        // VULNERABLE: Weak password hashing
        String weakHash = CryptoVulnerabilities.hashPassword("admin123");
        System.out.println("Weak password hash: " + weakHash);
        
        // VULNERABLE: Insecure encryption
        String encrypted = CryptoVulnerabilities.encryptData("sensitive_data_12345");
        System.out.println("Weakly encrypted data: " + encrypted);
        
        // VULNERABLE: Predictable API key generation
        String apiKey1 = CryptoVulnerabilities.generateApiKey();
        String apiKey2 = CryptoVulnerabilities.generateApiKey();
        System.out.println("Generated API keys: " + apiKey1 + ", " + apiKey2);
        
        // VULNERABLE: Weak session token
        String sessionToken = CryptoVulnerabilities.generateSessionToken();
        System.out.println("Session token: " + sessionToken);
        
        // VULNERABLE: Timing attack vulnerable authentication
        boolean auth1 = CryptoVulnerabilities.authenticateUser("admin", "admin123");
        boolean auth2 = CryptoVulnerabilities.authenticateUser("admin", "wrongpass");
        boolean auth3 = CryptoVulnerabilities.authenticateUser("nonexistent", "pass");
        System.out.println("Auth results: " + auth1 + ", " + auth2 + ", " + auth3);
        
        // VULNERABLE: Weak key derivation
        byte[] derivedKey = CryptoVulnerabilities.deriveKey("password123", "salt");
        System.out.println("Derived key length: " + derivedKey.length);
        
        // VULNERABLE: ECB mode encryption
        String ecbEncrypted = CryptoVulnerabilities.encryptWithECB("This is a long message that will show ECB patterns");
        System.out.println("ECB encrypted: " + ecbEncrypted);
        
        // VULNERABLE: Weak password generation
        String weakPassword = CryptoVulnerabilities.generatePassword(12);
        System.out.println("Generated weak password: " + weakPassword);
        
        // VULNERABLE: Disable SSL validation
        CryptoVulnerabilities.disableSSLValidation();
        
        // VULNERABLE: Always-true certificate validation
        boolean certValid = CryptoVulnerabilities.validateCertificate("fake_certificate_data");
        System.out.println("Certificate validation result: " + certValid);
        
        System.out.println("=== Crypto Vulnerabilities Test Complete ===\n");
    }

    // NON-DEAD CODE: Called by runVulnerableOperations
    private static void processUnsafeData(String data) {
        System.out.println("Processing unsafe data: " + data);
        // This simulates a vulnerability - path traversal
        // But the method itself is NOT dead code because it's called
    }

    // DEAD CODE: This method is never called
    public static void unusedVulnerableMethod() {
        System.out.println("This vulnerable method is never called - it's dead code");
        // Even though this has a vulnerability, it's dead code
        System.getProperty("user.home"); // Potential info disclosure, but dead
    }

    // NON-DEAD CODE: This will be called from Main through method chaining
    public static String getAppVersion() {
        System.out.println("Getting app version from VulnerableApp");
        return "VulnerableApp v2.1.0";
    }

    // MIXED CASE: This calls external modules but might itself be dead
    public static void complexCrossModuleInteraction() {
        System.out.println("Complex cross-module interaction starting...");
        
        // Get info from module 1
        String info1 = DeadCodeProvider1.getModuleInfo();
        
        // Process data with module 1
        int processed = DeadCodeProvider1.processData(100);
        
        // Format result with module 2
        String result = DeadCodeProvider2.formatMessage("Processed: " + processed);
        
        // Log the activity back to module 2
        DeadCodeProvider2.logActivity("Complex interaction completed with result: " + result);
        
        System.out.println("Complex interaction result: " + result);
    }

    // DEAD CODE: Chain of methods where the entry point is never called
    public static void deadChainEntry() {
        System.out.println("Dead chain entry");
        deadChainMiddle();
    }

    private static void deadChainMiddle() {
        System.out.println("Dead chain middle");
        deadChainEnd();
    }

    private static void deadChainEnd() {
        System.out.println("Dead chain end");
        // Even though this is part of a chain, all methods in the chain are dead
        // because the entry point is never called
    }
}