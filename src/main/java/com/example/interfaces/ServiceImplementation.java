package com.example.interfaces;

import com.example.moredeadcode.DeadCodeProvider1;

public class ServiceImplementation implements ServiceInterface {

    // NON-DEAD CODE: Implementation of interface method, will be live if this class is used
    @Override
    public void performService() {
        System.out.println("ServiceImplementation.performService() executing...");
        
        // Call to other module - reinforces that DeadCodeProvider1.getModuleInfo is NOT dead
        String info = DeadCodeProvider1.getModuleInfo();
        System.out.println("Service got module info: " + info);
        
        // Call helper method
        processServiceData();
    }

    // NON-DEAD CODE: Called by performService
    private void processServiceData() {
        System.out.println("Processing service data...");
        
        // Validate some data using external module
        boolean valid = DeadCodeProvider1.validateInput("service_data_123");
        System.out.println("Service data validation: " + valid);
    }

    // Override default method - makes it NOT dead if this implementation is used
    @Override
    public String getDefaultMessage() {
        return "Custom message from ServiceImplementation";
    }

    // DEAD CODE: This method is never called
    public void unusedServiceMethod() {
        System.out.println("This service method is never called - dead code");
        
        // Even though it calls live methods, this method itself is dead
        performService();
    }

    // DEAD CODE: Static method never called
    public static void staticServiceMethod() {
        System.out.println("Static service method - dead code");
    }
}
