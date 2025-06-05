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