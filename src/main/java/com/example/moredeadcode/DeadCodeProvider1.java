package com.example.moredeadcode;

public class DeadCodeProvider1 {

    // This is a dead code method
    public static void utilityMethod1() {
        System.out.println("Executing utilityMethod1 from DeadCodeProvider1...");
        String unusedVariable = "This variable is not used.";
        for (int i = 0; i < 5; i++) {
            // This loop does nothing useful
        }
        System.out.println("utilityMethod1 finished.");
    }

    // Another dead code method in the same file
    public static int calculateSomethingUnused(int a, int b) {
        System.out.println("Calculating something unused in DeadCodeProvider1...");
        return a + b * 2; // The result of this method is never used
    }

    // NON-DEAD CODE: This method will be called from Main.java
    public static String getModuleInfo() {
        System.out.println("DeadCodeProvider1.getModuleInfo() called from external module");
        return "DeadCodeProvider1 v1.0 - Active Module";
    }

    // NON-DEAD CODE: This method will be called from DeadCodeProvider2
    public static int processData(int input) {
        System.out.println("Processing data in DeadCodeProvider1: " + input);
        return input * 3 + 7; // Some processing logic
    }

    // NON-DEAD CODE: This method will be called from VulnerableApp
    public static boolean validateInput(String input) {
        System.out.println("Validating input in DeadCodeProvider1: " + input);
        return input != null && input.length() > 0 && input.length() < 100;
    }

    // POTENTIALLY DEAD CODE: This method calls another method in same class
    public static void internalChainMethod1() {
        System.out.println("Internal chain method 1");
        internalChainMethod2(); // This makes internalChainMethod2 NOT dead if this method is called
    }

    // This method is called by internalChainMethod1, so it's NOT dead if internalChainMethod1 is called
    private static void internalChainMethod2() {
        System.out.println("Internal chain method 2 - called from internalChainMethod1");
    }
}
