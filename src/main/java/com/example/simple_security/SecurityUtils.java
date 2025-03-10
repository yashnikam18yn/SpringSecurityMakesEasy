package com.example.simple_security;

import org.springframework.stereotype.Component;

@Component
public class SecurityUtils {

    /**
     * Returns a simple greeting message.
     * @return Greeting message.
     */
    public String getGreeting() {
        return "Hello from EasySecurity Framework!";
    }
}
