package com.example.moredeadcode;

public class DeadCodeProvider2 {

    // This is another dead code method in a different file
    public static void anotherUtilityMethod() {
        System.out.println("Executing anotherUtilityMethod from DeadCodeProvider2...");
        if (System.currentTimeMillis() % 2 == 0) {
            System.out.println("Current time is even.");
        } else {
            System.out.println("Current time is odd.");
        }
        // This method doesn't affect the program state outside of its own scope
        // and is not called from anywhere.
    }

    private static void helperForDeadCode() {
        System.out.println("This is a private helper method for a dead code method.");
        // It's also dead code because its caller is dead code.
    }

    public static String getUnusedConfigValue() {
        System.out.println("Fetching an unused configuration value from DeadCodeProvider2...");
        helperForDeadCode(); // Calling another dead method
        return "configValue123"; // This value is never retrieved or used
    }

    // NON-DEAD CODE: This method will be called from Main.java
    public static void performCrossModuleOperation() {
        System.out.println("DeadCodeProvider2.performCrossModuleOperation() called from Main");
        
        // Call a method from DeadCodeProvider1 - making that method NOT dead
        int result = DeadCodeProvider1.processData(42);
        System.out.println("Result from DeadCodeProvider1.processData(): " + result);
        
        // Call internal helper method - making it NOT dead
        String status = getSystemStatus();
        System.out.println("System status: " + status);
    }

    // NON-DEAD CODE: This helper method is called by performCrossModuleOperation
    private static String getSystemStatus() {
        System.out.println("Getting system status in DeadCodeProvider2");
        return "System is operational";
    }

    // NON-DEAD CODE: This method will be called from VulnerableApp
    public static String formatMessage(String message) {
        System.out.println("Formatting message in DeadCodeProvider2: " + message);
        return "[FORMATTED] " + message.toUpperCase() + " [END]";
    }

    // NON-DEAD CODE: This method will be called from DeadCodeProvider1 indirectly
    public static void logActivity(String activity) {
        System.out.println("DeadCodeProvider2 logging activity: " + activity);
        // This method demonstrates reverse dependency
    }

    // MIXED CASE: This method calls DeadCodeProvider1 but might itself be dead
    public static void possiblyDeadCrossModuleCall() {
        System.out.println("Possibly dead cross-module call");
        // This calls a NON-dead method in DeadCodeProvider1, but this method itself might be dead
        String info = DeadCodeProvider1.getModuleInfo();
        System.out.println("Got info: " + info);
    }
}
