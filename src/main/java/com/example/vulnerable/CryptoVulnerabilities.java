package com.example.vulnerable;

import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoVulnerabilities {

    // VULNERABILITY 1: Hardcoded encryption key
    private static final String HARDCODED_KEY = "MySecretKey12345"; // VULNERABLE: Hardcoded key
    private static final String WEAK_KEY = "12345"; // VULNERABLE: Weak key
    
    // VULNERABILITY 2: Weak hashing algorithm
    public static String hashPassword(String password) {
        try {
            // VULNERABLE: Using MD5 for password hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
            
        } catch (Exception e) {
            return "Hashing failed: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 3: Insecure encryption
    public static String encryptData(String data) {
        try {
            // VULNERABLE: Using DES (weak algorithm) with hardcoded key
            Cipher cipher = Cipher.getInstance("DES");
            SecretKeySpec keySpec = new SecretKeySpec(WEAK_KEY.getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
            
        } catch (Exception e) {
            return "Encryption failed: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 4: Predictable random numbers
    public static String generateApiKey() {
        // VULNERABLE: Using java.util.Random instead of SecureRandom
        java.util.Random random = new java.util.Random(System.currentTimeMillis()); // VULNERABLE: Predictable seed
        
        StringBuilder apiKey = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            apiKey.append(Integer.toHexString(random.nextInt(16)));
        }
        
        return "api_" + apiKey.toString();
    }
    
    // VULNERABILITY 5: Unsafe deserialization with ObjectInputStream
    public static Object deserializeObject(byte[] data) {
        try {
            // VULNERABLE: Deserializing without validation
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject(); // VULNERABLE: Can execute arbitrary code
            ois.close();
            
            return obj;
            
        } catch (Exception e) {
            System.err.println("Deserialization error: " + e.getMessage());
            return null;
        }
    }
    
    // VULNERABILITY 6: Weak SSL/TLS configuration
    public static void disableSSLValidation() {
        try {
            // VULNERABLE: Disabling SSL certificate validation
            javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
                new javax.net.ssl.X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                }
            };
            
            javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            
            System.out.println("SSL validation disabled"); // VULNERABLE: All certificates accepted
            
        } catch (Exception e) {
            System.err.println("SSL configuration error: " + e.getMessage());
        }
    }
    
    // VULNERABILITY 7: Information leakage through timing
    public static boolean authenticateUser(String username, String password) {
        String[] validUsers = {"admin", "user1", "user2", "testuser"};
        String[] validPasswords = {"admin123", "pass1", "pass2", "test123"};
        
        // VULNERABLE: Timing attack - different execution times reveal information
        for (int i = 0; i < validUsers.length; i++) {
            if (validUsers[i].equals(username)) {
                // VULNERABLE: Password comparison has timing differences
                if (slowStringCompare(password, validPasswords[i])) {
                    return true;
                }
                break; // VULNERABLE: Early exit reveals username existence
            }
        }
        
        return false;
    }
    
    // VULNERABLE: Slow string comparison reveals information through timing
    private static boolean slowStringCompare(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false; // VULNERABLE: Length check reveals information
        
        for (int i = 0; i < a.length(); i++) {
            if (a.charAt(i) != b.charAt(i)) {
                return false; // VULNERABLE: Early exit on mismatch
            }
            
            // Simulate processing time
            try {
                Thread.sleep(1); // VULNERABLE: Timing side channel
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        return true;
    }
    
    // VULNERABILITY 8: Weak random token generation
    public static String generateSessionToken() {
        // VULNERABLE: Weak randomness for security-critical token
        long timestamp = System.currentTimeMillis();
        int random = new java.util.Random().nextInt(10000); // VULNERABLE: Weak random
        
        String token = "session_" + timestamp + "_" + random; // VULNERABLE: Predictable pattern
        return Base64.getEncoder().encodeToString(token.getBytes());
    }
    
    // VULNERABILITY 9: Insecure key derivation
    public static byte[] deriveKey(String password, String salt) {
        try {
            // VULNERABLE: Using simple SHA-1 instead of proper PBKDF2
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(salt.getBytes());
            byte[] key = md.digest(password.getBytes()); // VULNERABLE: Single iteration
            
            return key;
            
        } catch (Exception e) {
            System.err.println("Key derivation error: " + e.getMessage());
            return new byte[0];
        }
    }
    
    // VULNERABILITY 10: ECB mode encryption
    public static String encryptWithECB(String data) {
        try {
            // VULNERABLE: Using ECB mode which reveals patterns
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // VULNERABLE: ECB mode
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
            
        } catch (Exception e) {
            return "ECB encryption failed: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 11: Always-true certificate validation
    public static boolean validateCertificate(String certificateData) {
        // VULNERABLE: Always returns true, bypassing certificate validation
        System.out.println("Validating certificate: " + certificateData.substring(0, Math.min(50, certificateData.length())) + "...");
        return true; // VULNERABLE: Never actually validates the certificate
    }
    
    // DEAD CODE: Vulnerable cryptographic operations that are never called
    public static String deadCryptoMethod(String sensitiveData) {
        try {
            // VULNERABLE but dead: ROT13 "encryption"
            StringBuilder result = new StringBuilder();
            for (char c : sensitiveData.toCharArray()) {
                if (c >= 'a' && c <= 'z') {
                    result.append((char) ('a' + (c - 'a' + 13) % 26));
                } else if (c >= 'A' && c <= 'Z') {
                    result.append((char) ('A' + (c - 'A' + 13) % 26));
                } else {
                    result.append(c);
                }
            }
            return result.toString(); // VULNERABLE: ROT13 is not encryption
            
        } catch (Exception e) {
            return "Dead crypto failed";
        }
    }
    
    // DEAD CODE: SQL Injection vulnerability that's never called
    private static String deadSqlQuery(String userInput) {
        // VULNERABLE but dead: SQL injection
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'"; // VULNERABLE: SQL injection
        System.out.println("Executing query: " + query);
        return query;
    }
    
    // DEAD CODE: Path traversal vulnerability that's never called
    private static String deadFileAccess(String filename) {
        // VULNERABLE but dead: Path traversal
        String filePath = "/var/data/" + filename; // VULNERABLE: No path sanitization
        return filePath;
    }
    
    // DEAD CODE: Command injection vulnerability that's never called
    private static void deadCommandExecution(String userCommand) {
        try {
            // VULNERABLE but dead: Command injection
            String command = "ping " + userCommand; // VULNERABLE: No input validation
            Runtime.getRuntime().exec(command); // VULNERABLE: Command injection
        } catch (Exception e) {
            System.err.println("Dead command failed: " + e.getMessage());
        }
    }
    
    // DEAD CODE: XSS vulnerability that's never called
    private static String deadXssMethod(String userInput) {
        // VULNERABLE but dead: XSS
        return "<div>User said: " + userInput + "</div>"; // VULNERABLE: No HTML escaping
    }
    
    // DEAD CODE: Hardcoded credentials that are never used
    private static final String DEAD_DATABASE_PASSWORD = "admin123"; // VULNERABLE but dead
    private static final String DEAD_API_KEY = "sk-1234567890abcdef"; // VULNERABLE but dead
    
    private static boolean deadAuthMethod(String username, String password) {
        // VULNERABLE but dead: Hardcoded credentials
        return "admin".equals(username) && DEAD_DATABASE_PASSWORD.equals(password);
    }
    
    // DEAD CODE: Weak encryption with null IV that's never called
    private static String deadWeakEncryption(String data) {
        try {
            // VULNERABLE but dead: Null IV in CBC mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(new byte[16])); // VULNERABLE: Null IV
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            return "Dead encryption failed";
        }
    }
    
    // DEAD CODE: Information disclosure that's never called
    private static void deadErrorHandling(String operation) {
        try {
            // Simulate some operation
            throw new RuntimeException("Simulated error");
        } catch (Exception e) {
            // VULNERABLE but dead: Stack trace disclosure
            e.printStackTrace(); // VULNERABLE: Sensitive information disclosure
            System.out.println("Error in operation: " + operation + " - " + e.getMessage());
        }
    }
    
    // DEAD CODE: Insecure random for cryptographic purposes that's never called
    private static byte[] deadGenerateKey() {
        // VULNERABLE but dead: Using Math.random() for cryptographic key
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (Math.random() * 256); // VULNERABLE: Math.random() not cryptographically secure
        }
        return key;
    }
    
    // DEAD CODE: Vulnerable hash comparison that's never called
    private static boolean deadHashComparison(String input, String storedHash) {
        try {
            // VULNERABLE but dead: Using MD5 and vulnerable comparison
            MessageDigest md = MessageDigest.getInstance("MD5"); // VULNERABLE: MD5 is weak
            byte[] inputHash = md.digest(input.getBytes());
            String inputHashStr = Base64.getEncoder().encodeToString(inputHash);
            
            // VULNERABLE but dead: String comparison instead of constant-time
            return inputHashStr.equals(storedHash); // VULNERABLE: Timing attack possible
        } catch (Exception e) {
            return false;
        }
    }
      // DEAD CODE: Unreachable code with vulnerabilities
    private static void deadUnreachableCode() {
        // VULNERABLE but dead: Multiple vulnerabilities (commented out to avoid unreachable code error)
        // String password = "hardcoded123"; // VULNERABLE: Hardcoded password
        // String sql = "DELETE FROM users WHERE id = " + Math.random(); // VULNERABLE: SQL injection pattern
        // System.setProperty("java.security.debug", "all"); // VULNERABLE: Debug information exposure
        return; // Return moved to end to make method compilable
    }
    
    // DEAD CODE: Deprecated cryptographic method that's never called
    @Deprecated
    private static String deadDeprecatedCrypto(String data) {
        try {
            // VULNERABLE but dead: Using deprecated cipher
            Cipher cipher = Cipher.getInstance("RC4"); // VULNERABLE: RC4 is broken
            SecretKeySpec keySpec = new SecretKeySpec("weak".getBytes(), "RC4");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            return "Deprecated crypto failed";
        }
    }
    
    // DEAD CODE: Never called method with multiple chained vulnerabilities
    private static void deadVulnerabilityChain(String userInput) {
        // VULNERABLE but dead: Multiple vulnerabilities in sequence
        String filename = "../../../etc/passwd/" + userInput; // VULNERABLE: Path traversal
        String command = "cat " + filename; // VULNERABLE: Command injection
        String html = "<script>alert('" + userInput + "')</script>"; // VULNERABLE: XSS
        String sql = "INSERT INTO logs VALUES ('" + userInput + "')"; // VULNERABLE: SQL injection
        
        // This method is dead code but contains multiple vulnerability patterns
        System.out.println("Dead vulnerability chain executed");
    }
    
    // VULNERABILITY 12: Weak password generation
    public static String generatePassword(int length) {
        // VULNERABLE: Weak character set and predictable pattern
        String chars = "abc123"; // VULNERABLE: Very limited character set
        StringBuilder password = new StringBuilder();
        
        java.util.Random random = new java.util.Random(42); // VULNERABLE: Fixed seed
        
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return password.toString();
    }
    
    // DEAD CODE VULNERABILITIES - These functions are never called, testing for false positives
    
    // DEAD CODE VULNERABILITY 1: Hardcoded credentials in unused function
    private static String deadCodeLogin(String username) {
        // VULNERABLE but dead: Hardcoded admin credentials
        String adminUser = "admin";
        String adminPass = "admin123"; // VULNERABLE: Hardcoded password
        
        if (username.equals(adminUser)) {
            return "Welcome " + adminPass; // VULNERABLE: Password in return
        }
        return "Access denied";
    }
    
    // DEAD CODE VULNERABILITY 2: SQL injection in unused function
    private static String deadCodeSqlQuery(String userId) {
        // VULNERABLE but dead: SQL injection vulnerability
        String query = "SELECT * FROM users WHERE id = '" + userId + "'"; // VULNERABLE: SQL injection
        System.out.println("Executing: " + query);
        return query;
    }
    
    // DEAD CODE VULNERABILITY 3: Path traversal in unused function
    private static String deadCodeFileAccess(String filename) {
        // VULNERABLE but dead: Path traversal vulnerability
        String basePath = "/app/data/";
        String fullPath = basePath + filename; // VULNERABLE: No path validation
        
        try {
            java.nio.file.Files.readAllLines(java.nio.file.Paths.get(fullPath));
            return "File read: " + fullPath;
        } catch (Exception e) {
            return "Error reading file";
        }
    }
    
    // DEAD CODE VULNERABILITY 4: Command injection in unused function
    private static String deadCodeExecuteCommand(String userInput) {
        try {
            // VULNERABLE but dead: Command injection
            String command = "ping " + userInput; // VULNERABLE: No input sanitization
            Process process = Runtime.getRuntime().exec(command); // VULNERABLE: Command injection
            return "Command executed: " + command;
        } catch (Exception e) {
            return "Command failed";
        }
    }
    
    // DEAD CODE VULNERABILITY 5: Weak crypto in unused function
    private static String deadCodeWeakEncryption(String data) {
        try {
            // VULNERABLE but dead: XOR "encryption" with fixed key
            byte[] key = {0x42}; // VULNERABLE: Single byte XOR key
            byte[] input = data.getBytes();
            byte[] output = new byte[input.length];
            
            for (int i = 0; i < input.length; i++) {
                output[i] = (byte) (input[i] ^ key[0]); // VULNERABLE: Weak XOR encryption
            }
            
            return Base64.getEncoder().encodeToString(output);
        } catch (Exception e) {
            return "Encryption failed";
        }
    }
    
    // DEAD CODE VULNERABILITY 6: Information disclosure in unused function
    private static void deadCodeLogSensitiveData(String username, String password, String ssn) {
        // VULNERABLE but dead: Logging sensitive information
        System.out.println("Login attempt - User: " + username + 
                          ", Password: " + password + // VULNERABLE: Password logging
                          ", SSN: " + ssn); // VULNERABLE: PII logging
    }
    
    // DEAD CODE VULNERABILITY 7: Insecure random in unused function
    private static String deadCodeGenerateToken() {
        // VULNERABLE but dead: Predictable token generation
        long timestamp = 1234567890L; // VULNERABLE: Fixed timestamp
        int counter = 1; // VULNERABLE: Predictable counter
        
        String token = "token_" + timestamp + "_" + counter; // VULNERABLE: Predictable pattern
        return token;
    }
    
    // DEAD CODE VULNERABILITY 8: Buffer overflow simulation in unused function
    private static String deadCodeBufferIssue(String input) {
        // VULNERABLE but dead: Potential buffer issues
        char[] buffer = new char[10];
        char[] inputChars = input.toCharArray();
        
        // VULNERABLE: No bounds checking
        for (int i = 0; i < inputChars.length; i++) {
            if (i < buffer.length) {
                buffer[i] = inputChars[i];
            }
            // VULNERABLE: Silent truncation without validation
        }
        
        return new String(buffer);
    }
    
    // DEAD CODE VULNERABILITY 9: XXE vulnerability in unused function
    private static String deadCodeParseXml(String xmlData) {
        try {
            // VULNERABLE but dead: XXE vulnerability
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // VULNERABLE: XXE not disabled
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            
            java.io.StringReader reader = new java.io.StringReader(xmlData);
            org.w3c.dom.Document doc = builder.parse(new org.xml.sax.InputSource(reader));
            
            return "XML parsed successfully";
        } catch (Exception e) {
            return "XML parsing failed";
        }
    }
    
    // DEAD CODE VULNERABILITY 10: LDAP injection in unused function
    private static String deadCodeLdapQuery(String username) {
        // VULNERABLE but dead: LDAP injection
        String filter = "(uid=" + username + ")"; // VULNERABLE: No LDAP escaping
        String ldapQuery = "ou=people,dc=example,dc=com";
        
        System.out.println("LDAP filter: " + filter);
        return "LDAP query: " + ldapQuery + " with filter: " + filter;
    }
    
    // DEAD CODE VULNERABILITY 11: Race condition in unused function
    private static int deadCodeCounter = 0;
    private static String deadCodeRaceCondition() {
        // VULNERABLE but dead: Race condition on shared state
        deadCodeCounter++; // VULNERABLE: Non-atomic operation on shared variable
        
        try {
            Thread.sleep(10); // Simulate processing
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        return "Counter value: " + deadCodeCounter; // VULNERABLE: Inconsistent state
    }
    
    // DEAD CODE VULNERABILITY 12: Regex DoS in unused function
    private static boolean deadCodeRegexDoS(String input) {
        // VULNERABLE but dead: Catastrophic backtracking
        String pattern = "(a+)+b"; // VULNERABLE: Exponential regex complexity
        
        try {
            return input.matches(pattern);
        } catch (Exception e) {
            return false;
        }
    }
    
    // DEAD CODE VULNERABILITY 13: Insecure deserialization variant
    private static Object deadCodeUnsafeDeserialize(String base64Data) {
        try {
            // VULNERABLE but dead: Another deserialization vulnerability
            byte[] data = Base64.getDecoder().decode(base64Data);
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(data));
            
            Object result = ois.readObject(); // VULNERABLE: Unsafe deserialization
            ois.close();
            
            return result;
        } catch (Exception e) {
            return null;
        }
    }
}
