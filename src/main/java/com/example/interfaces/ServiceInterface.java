package com.example.interfaces;

public interface ServiceInterface {
    
    // Interface method - will be live if any implementation is used
    void performService();
    
    // Default method in interface - might be dead if not overridden or called
    default String getDefaultMessage() {
        return "Default service message";
    }
    
    // Static method in interface - dead if never called
    static void staticInterfaceMethod() {
        System.out.println("Static method in ServiceInterface - this is dead code");
    }
}
