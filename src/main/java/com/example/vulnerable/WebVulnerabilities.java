package com.example.vulnerable;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class WebVulnerabilities {
    
    private static final Logger logger = Logger.getLogger(WebVulnerabilities.class.getName());
    
    // VULNERABILITY 1: Cross-Site Scripting (XSS)
    public static String generateUserProfile(String username, String bio) {
        // VULNERABLE: Direct insertion of user input into HTML without escaping
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Welcome " + username + "</h1>"); // VULNERABLE: XSS
        html.append("<p>Bio: " + bio + "</p>"); // VULNERABLE: XSS
        html.append("</body></html>");
        
        return html.toString();
    }
    
    // VULNERABILITY 2: Server-Side Request Forgery (SSRF)
    public static String fetchExternalData(String url) {
        try {
            // VULNERABLE: No URL validation - can access internal services
            URL targetUrl = new URL(url); // VULNERABLE: User-controlled URL
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            return response.toString();
            
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage(); // VULNERABLE: Error details exposed
        }
    }
    
    // VULNERABILITY 3: Unsafe deserialization
    public static Object deserializeUserData(byte[] serializedData) {
        try {
            // VULNERABLE: Deserializing untrusted data
            ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object userData = ois.readObject(); // VULNERABLE: Unsafe deserialization
            ois.close();
            
            return userData;
            
        } catch (Exception e) {
            logger.severe("Deserialization failed: " + e.getMessage());
            return null;
        }
    }
    
    // VULNERABILITY 4: XML External Entity (XXE)
    public static String parseXmlConfig(String xmlContent) {
        try {
            // VULNERABLE: XML parser without disabling external entities
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            ByteArrayInputStream xmlStream = new ByteArrayInputStream(xmlContent.getBytes());
            
            org.w3c.dom.Document doc = builder.parse(xmlStream); // VULNERABLE: XXE possible
            
            return "XML parsed successfully: " + doc.getDocumentElement().getTagName();
            
        } catch (Exception e) {
            return "XML parsing error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 5: Hardcoded credentials
    private static final String API_KEY = "sk-1234567890abcdef"; // VULNERABLE: Hardcoded secret
    private static final String DB_PASSWORD = "admin123"; // VULNERABLE: Hardcoded password
    private static final String JWT_SECRET = "mySecretKey2023!"; // VULNERABLE: Hardcoded JWT secret
    
    public static String connectToService() {
        // VULNERABLE: Using hardcoded credentials
        return "Connecting with API key: " + API_KEY;
    }
    
    // VULNERABILITY 6: Weak cryptography
    public static String weakEncryption(String data) {
        try {
            // VULNERABLE: Using weak MD5 algorithm
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(data.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            
            return sb.toString();
            
        } catch (Exception e) {
            return "Encryption failed";
        }
    }
    
    // VULNERABILITY 7: Information disclosure in logs
    public static void processLogin(String username, String password, String sessionToken) {
        // VULNERABLE: Logging sensitive information
        logger.info("Login attempt for user: " + username);
        logger.info("Password provided: " + password); // VULNERABLE: Password in logs
        logger.info("Session token: " + sessionToken); // VULNERABLE: Token in logs
        
        if (password.equals("admin")) {
            logger.info("Admin login successful with token: " + sessionToken);
        }
    }
    
    // VULNERABILITY 8: Directory traversal in file operations
    public static String readConfigFile(String fileName) {
        try {
            // VULNERABLE: No path validation
            String configPath = "/app/config/" + fileName; // VULNERABLE: Path traversal possible
            
            BufferedReader reader = new BufferedReader(new FileReader(configPath));
            StringBuilder content = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            
            return content.toString();
            
        } catch (IOException e) {
            return "Config read error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 9: Insecure random number generation
    public static String generateSessionId() {
        // VULNERABLE: Using weak random number generator
        java.util.Random random = new java.util.Random(); // VULNERABLE: Not cryptographically secure
        long sessionId = random.nextLong();
        
        return "SESSION_" + Math.abs(sessionId);
    }
    
    // VULNERABILITY 10: Race condition
    private static int counter = 0;
    
    public static String incrementCounter(String userId) {
        // VULNERABLE: Race condition - not thread-safe
        int currentValue = counter; // VULNERABLE: Non-atomic read
        
        try {
            Thread.sleep(10); // Simulate processing time
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        counter = currentValue + 1; // VULNERABLE: Non-atomic write
        
        return "User " + userId + " got counter value: " + counter;
    }
    
    // DEAD CODE: Vulnerable method that's never called
    public static void deadVulnerableWebMethod(String userInput) {
        // VULNERABLE but dead code
        Runtime runtime = Runtime.getRuntime();
        try {
            // This would be command injection if it were called
            runtime.exec("curl " + userInput); // VULNERABLE: Command injection in dead code
        } catch (IOException e) {
            logger.severe("Dead code command failed");
        }
    }
    
    // VULNERABILITY 11: Improper input validation
    public static String processAge(String ageInput) {
        try {
            // VULNERABLE: No input validation before parsing
            int age = Integer.parseInt(ageInput); // VULNERABLE: Can cause NumberFormatException
            
            if (age < 0) {
                return "Invalid age: " + age;
            } else if (age > 150) {
                return "Suspicious age: " + age; // VULNERABLE: Information disclosure
            }
            
            return "Age processed: " + age;
            
        } catch (NumberFormatException e) {
            return "Age parsing error: " + ageInput + " - " + e.getMessage(); // VULNERABLE: Input echoed back
        }
    }
    
    // VULNERABILITY 12: Unsafe file upload handling
    public static String handleFileUpload(String fileName, byte[] fileContent) {
        try {
            // VULNERABLE: No file type validation
            String uploadPath = "/tmp/uploads/" + fileName; // VULNERABLE: Path traversal possible
            
            FileOutputStream fos = new FileOutputStream(uploadPath);
            fos.write(fileContent); // VULNERABLE: No size limits or content validation
            fos.close();
            
            return "File uploaded to: " + uploadPath; // VULNERABLE: Path disclosure
            
        } catch (IOException e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}
