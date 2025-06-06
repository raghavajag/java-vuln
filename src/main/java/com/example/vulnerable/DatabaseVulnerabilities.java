package com.example.vulnerable;

import java.sql.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class DatabaseVulnerabilities {
    
    private static final Logger logger = Logger.getLogger(DatabaseVulnerabilities.class.getName());
    private static final String DB_URL = "jdbc:sqlite:users.db";
    
    // VULNERABLE: Fake sanitization that doesn't actually sanitize
    public static String fakeSanitizeInput(String userInput) {
        // This function pretends to sanitize but doesn't actually do anything secure
        if (userInput == null) return "";
        return userInput + "_safe"; // VULNERABLE: Just appends text, doesn't sanitize
    }
    
    // SECURE: Proper sanitization
    public static String sanitizeInput(String userInput) {
        if (userInput == null) return "";
        // Only allow alphanumeric characters
        return userInput.replaceAll("[^a-zA-Z0-9]", "");
    }
    
    // VULNERABILITY 1: SQL Injection with string concatenation
    public static String vulnerableUserLookup(String username) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            String safeInput = fakeSanitizeInput(username); // VULNERABLE: Fake sanitization
            
            // VULNERABLE: Direct string concatenation in SQL query
            String query = "SELECT * FROM users WHERE username = '" + safeInput + "'";
            logger.info("Executing query: " + query);
            
            ResultSet rs = stmt.executeQuery(query); // VULNERABLE: Executing unsanitized query
            
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("username")).append(":").append(rs.getString("email"));
            }
            
            conn.close();
            return result.toString();
            
        } catch (SQLException e) {
            logger.severe("Database error: " + e.getMessage());
            return "Error: " + e.getMessage(); // VULNERABLE: Exposing error details
        }
    }
    
    // VULNERABILITY 2: Another SQL injection pattern
    public static String getUserDetails(String userId, String role) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Multiple user inputs concatenated
            String query = "SELECT * FROM users WHERE id = " + userId + 
                          " AND role = '" + role + "'"; // No sanitization at all
            
            ResultSet rs = stmt.executeQuery(query);
            
            StringBuilder details = new StringBuilder();
            while (rs.next()) {
                details.append("User: ").append(rs.getString("username"))
                       .append(", Role: ").append(rs.getString("role"));
            }
            
            conn.close();
            return details.toString();
            
        } catch (SQLException e) {
            return "Database error occurred"; // Better error handling
        }
    }
    
    // VULNERABILITY 3: Dynamic query construction
    public static String searchUsers(String searchTerm, String orderBy) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            String processedInput = fakeSanitizeInput(searchTerm);
            
            // VULNERABLE: Dynamic ORDER BY clause
            String query = "SELECT username, email FROM users WHERE username LIKE '%" + 
                          processedInput + "%' ORDER BY " + orderBy; // VULNERABLE: orderBy not sanitized
            
            ResultSet rs = stmt.executeQuery(query);
            
            StringBuilder results = new StringBuilder();
            while (rs.next()) {
                results.append(rs.getString("username")).append(",");
            }
            
            conn.close();
            return results.toString();
            
        } catch (SQLException e) {
            logger.severe("Search failed: " + e.getMessage());
            throw new RuntimeException("Search operation failed", e); // VULNERABLE: Exception with sensitive info
        }
    }
    
    // SECURE ALTERNATIVE: Using PreparedStatement (this is NOT vulnerable)
    public static String secureUserLookup(String username) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            
            // SECURE: Using PreparedStatement with parameters
            String query = "SELECT * FROM users WHERE username = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, sanitizeInput(username)); // Proper sanitization + prepared statement
            
            ResultSet rs = pstmt.executeQuery();
            
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("username")).append(":").append(rs.getString("email"));
            }
            
            conn.close();
            return result.toString();
            
        } catch (SQLException e) {
            logger.warning("Secure lookup failed");
            return "Lookup failed"; // SECURE: No sensitive error details exposed
        }
    }
    
    // VULNERABILITY 4: Injection in UPDATE statement
    public static void updateUserRole(String username, String newRole) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Direct concatenation in UPDATE
            String updateQuery = "UPDATE users SET role = '" + newRole + 
                               "' WHERE username = '" + username + "'";
            
            stmt.executeUpdate(updateQuery); // VULNERABLE: No validation
            logger.info("Updated user: " + username + " to role: " + newRole);
            
            conn.close();
            
        } catch (SQLException e) {
            logger.severe("Update failed: " + e.getMessage());
        }
    }
    
    // DEAD CODE: This method is never called but contains vulnerabilities
    public static String deadVulnerableMethod(String input) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            // VULNERABLE but dead code
            String query = "DROP TABLE users; SELECT * FROM secrets WHERE key = '" + input + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            return "This dead code contains SQL injection";
            
        } catch (SQLException e) {
            return "Dead code error";
        }
    }
    
    // VULNERABILITY 5: Information disclosure through error messages
    public static String loginUser(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL);
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Password in query + SQL injection
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                return "Login successful for: " + rs.getString("username");
            } else {
                return "Login failed - user not found or invalid password"; // VULNERABLE: Information disclosure
            }
            
        } catch (SQLException e) {
            return "Login error: " + e.getClass().getSimpleName() + " - " + e.getMessage(); // VULNERABLE: Error details
        }
    }
}
