package com.example.utils;

import com.example.moredeadcode.DeadCodeProvider1;
import com.example.moredeadcode.DeadCodeProvider2;
import com.example.vulnerable.VulnerableApp;

public class ModuleOrchestrator {

    // DEAD CODE: This method is never called from anywhere
    public static void deadOrchestratorMethod() {
        System.out.println("This orchestrator method is dead code");
        // Even though it calls other modules, this method itself is dead
        String info = DeadCodeProvider1.getModuleInfo();
        System.out.println("Dead orchestrator got: " + info);
    }

    // NON-DEAD CODE: This will be called from Main
    public static void orchestrateModules() {
        System.out.println("Orchestrating all modules...");
        
        // Test validation across modules
        String testInput = "cross_module_test";
        boolean isValid = DeadCodeProvider1.validateInput(testInput);
        
        if (isValid) {
            // Chain multiple module calls
            int processed = DeadCodeProvider1.processData(testInput.length());
            String formatted = DeadCodeProvider2.formatMessage("Processed length: " + processed);
            System.out.println("Orchestration result: " + formatted);
            
            // Log the activity
            DeadCodeProvider2.logActivity("Orchestration completed successfully");
        }
        
        // Call vulnerable app operations
        VulnerableApp.runVulnerableOperations();
        
        // Test some edge cases
        testEdgeCases();
    }

    // NON-DEAD CODE: Called by orchestrateModules
    private static void testEdgeCases() {
        System.out.println("Testing edge cases in ModuleOrchestrator...");
        
        // Test with empty input
        boolean validEmpty = DeadCodeProvider1.validateInput("");
        System.out.println("Empty input valid: " + validEmpty);
        
        // Test with null input
        boolean validNull = DeadCodeProvider1.validateInput(null);
        System.out.println("Null input valid: " + validNull);
        
        // Test formatting with special characters
        String specialFormatted = DeadCodeProvider2.formatMessage("Special!@#$%");
        System.out.println("Special formatted: " + specialFormatted);
    }

    // DEAD CODE: Complex method that calls many others but is never called itself
    public static void complexDeadMethod() {
        System.out.println("Complex dead method starting...");
        
        // This method calls many non-dead methods, but this method itself is dead
        orchestrateModules(); // This call doesn't make orchestrateModules dead
        
        String version = VulnerableApp.getAppVersion();
        System.out.println("Version in dead method: " + version);
        
        // Even call the possibly dead method from DeadCodeProvider2
        DeadCodeProvider2.possiblyDeadCrossModuleCall();
        
        System.out.println("Complex dead method completed");
    }

    // DEAD CODE: Method with recursive call (still dead if entry point is never called)
    public static void recursiveDeadMethod(int depth) {
        if (depth <= 0) return;
        
        System.out.println("Recursive dead method, depth: " + depth);
        recursiveDeadMethod(depth - 1);
        
        // Even with recursion, this is dead code if never called from a live path
    }

    // DEAD CODE: Static initializer block that's never executed (in practice, this would run at class loading)
    static {
        System.out.println("ModuleOrchestrator static block - this might be considered live or dead depending on analysis");
        // This block runs when the class is first loaded, so it might be considered "live"
        // even if no methods are called, but it depends on the analysis tool
    }
}
