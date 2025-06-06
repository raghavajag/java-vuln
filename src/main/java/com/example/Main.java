package com.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import com.example.moredeadcode.DeadCodeProvider1;
import com.example.moredeadcode.DeadCodeProvider2;
import com.example.vulnerable.VulnerableApp;
import com.example.utils.ModuleOrchestrator;
import com.example.interfaces.ServiceInterface;
import com.example.interfaces.ServiceImplementation;

public class Main {

    public static void main(String[] args) {
        System.out.println("Starting vulnerable application...");
        String username = args.length > 0 ? args[0] : "guest";
        vulnerableMethod(username);
          // Call cross-module functions - making them NOT dead code
        demonstrateCrossModuleInteractions();
          // Call the module orchestrator - makes it NOT dead code
        ModuleOrchestrator.orchestrateModules();
        
        // Test interface implementation - makes it NOT dead code
        testInterfaceImplementation();
        
        // deadCodeMethod is never called - so it remains DEAD CODE
        System.out.println("Application finished.");
    }

    // NON-DEAD CODE: Called from main
    public static void demonstrateCrossModuleInteractions() {
        System.out.println("\n=== Demonstrating Cross-Module Interactions ===");
        
        // Call method from DeadCodeProvider1 - makes it NOT dead
        String moduleInfo = DeadCodeProvider1.getModuleInfo();
        System.out.println("Module 1 Info: " + moduleInfo);
        
        // Call method from DeadCodeProvider2 - makes it NOT dead  
        DeadCodeProvider2.performCrossModuleOperation();
        
        // Call method from VulnerableApp - makes it NOT dead
        VulnerableApp.runVulnerableOperations();
        
        // Get app version - makes it NOT dead
        String version = VulnerableApp.getAppVersion();
        System.out.println("App Version: " + version);
        
        // Call internal method that calls external modules
        conditionalCrossModuleCall();
          System.out.println("=== Cross-Module Interactions Complete ===\n");
    }

    // NON-DEAD CODE: Called from main
    private static void testInterfaceImplementation() {
        System.out.println("\n=== Testing Interface Implementation ===");
        
        // Create instance - makes ServiceImplementation NOT dead
        ServiceInterface service = new ServiceImplementation();
        
        // Call interface method - makes performService NOT dead
        service.performService();
        
        // Call default method - makes the overridden version NOT dead
        String message = service.getDefaultMessage();
        System.out.println("Service message: " + message);
        
        System.out.println("=== Interface Implementation Test Complete ===\n");
    }

    // NON-DEAD CODE: Called by demonstrateCrossModuleInteractions
    private static void conditionalCrossModuleCall() {
        if (Math.random() > 0.5) {
            // This makes internalChainMethod1 in DeadCodeProvider1 NOT dead
            DeadCodeProvider1.internalChainMethod1();
        } else {
            // This keeps complexCrossModuleInteraction alive, but it might still be considered
            // dead if static analysis can't determine the random condition
            VulnerableApp.complexCrossModuleInteraction();
        }
    }    public static void vulnerableMethod(String userInput) {
        // Vulnerability 1: Path Traversal
        // If userInput is something like "../../etc/passwd", it could read sensitive files.
        String basePath = "/tmp/user_files/"; // Intended base directory
        File userFile = new File(basePath + userInput); // VULNERABLE: Direct concatenation

        System.out.println("Attempting to read file: " + userFile.getAbsolutePath());

        if (userFile.exists() && !userFile.isDirectory()) {
            try {
                // VULNERABLE: No path validation before reading
                String content = new String(Files.readAllBytes(Paths.get(userFile.getAbsolutePath())));
                System.out.println("File Content:\n" + content);
            } catch (IOException e) {
                System.err.println("Error reading file: " + e.getMessage());
            }
        } else {
            System.out.println("File not found or is a directory: " + userFile.getAbsolutePath());
        }

        // Vulnerability 2: Command Injection
        try {
            // VULNERABLE: Directly using user input in command execution
            Runtime runtime = Runtime.getRuntime();
            String command = "ls -la " + userInput; // VULNERABLE: User input in command
            Process process = runtime.exec(command);
            System.out.println("Command executed: " + command);
        } catch (IOException e) {
            System.err.println("Command execution failed: " + e.getMessage());
        }
    }

    // Dead code: This method is never called
    public static void deadCodeMethod() {
        System.out.println("This is a dead code method. It should be flagged by CodeQL.");
        int x = 10;
        int y = 20;
        int sum = x + y;
        System.out.println("Sum: " + sum); // This line will also be dead if the method is dead
    }

    // Another dead code method, perhaps more complex
    private void unusedPrivateMethod(String message) {
        if (message != null && !message.isEmpty()) {
            System.out.println("Unused private method received: " + message.toUpperCase());
        } else {
            System.out.println("Unused private method received no message.");
        }
    }
    public static void newMethod() { // Renamed from 'new'
        System.out.println("This is a dead code method. It should be flagged by CodeQL.");
        int x = 10;
        int y = 20;
        int sum = x + y;
        System.out.println("Sum: " + sum); // This line will also be dead if the method is dead
    }

    private static void new2(String message) {
        System.out.println("This is a dead code method. It should be flagged by CodeQL.");
        int x = 10;
        int y = 20;
        int sum = x + y;
        System.out.println("Sum: " + sum); // This line will also be dead if the method is dead
    }
}
