package com.example.interfaces;

// DEAD CODE: This entire class is never instantiated or used
public class UnusedServiceImplementation implements ServiceInterface {

    @Override
    public void performService() {
        System.out.println("UnusedServiceImplementation.performService() - this is dead code");
        // Even though this implements the interface, it's dead code because the class is never used
    }

    public void anotherUnusedMethod() {
        System.out.println("Another unused method in dead class");
    }
}
