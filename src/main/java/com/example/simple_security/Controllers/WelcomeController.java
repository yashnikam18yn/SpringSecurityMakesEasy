package com.example.simple_security.Controllers;

import com.example.simple_security.UserUse.UserTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class WelcomeController {

    @Autowired
    private UserTest userTest;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome to the security";
    }

    @GetMapping("/get-token")
    public ResponseEntity<?> getToken(@RequestParam(defaultValue = "30") long expirationMinutes) {
        String token = userTest.createToken("yash", expirationMinutes);
        return ResponseEntity.ok()
                .body(Map.of(
                        "token", token,
                        "expiresIn", expirationMinutes + " minutes",
                        "username", userTest.getUsernameFromToken(token)
                ));
    }



    @GetMapping("/extract-username")
    public ResponseEntity<?> extractUsername(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            String username = userTest.getUsernameFromToken(token);
            
            if (username != null) {
                return ResponseEntity.ok()
                        .body(Map.of(
                                "username", username,
                                "token", token
                        ));
            } else {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "error", "Invalid token",
                                "message", "Could not extract username from token"
                        ));
            }
        }
        return ResponseEntity.badRequest()
                .body(Map.of(
                        "error", "Invalid token format",
                        "message", "Token must start with 'Bearer '"
                ));
    }

    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            boolean isValid = userTest.validateUserToken(token);
            String username = userTest.getUsernameFromToken(token);
            
            if (isValid) {
                return ResponseEntity.ok()
                        .body(Map.of(
                                "valid", true,
                                "username", username,
                                "message", "Token is valid"
                        ));
            } else {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "valid", false,
                                "message", "Token is invalid or expired"
                        ));
            }
        }
        return ResponseEntity.badRequest()
                .body(Map.of(
                        "error", "Invalid token format",
                        "message", "Token must start with 'Bearer '"
                ));
    }

    @GetMapping("/home")
    public String home() {
        return "Home Page";
    }
}
