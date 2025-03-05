package com.example.simple_security.UserUse;

import com.example.simple_security.config.EasySecurity;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

@Configuration
public class UserTest extends EasySecurity {
    @Override
    public List<String> permittedUrls() {
        return List.of("/welcome", "get-token");
    }

    @Override
    public List<String> authenticatedUrls() {
        return List.of("/home");
    }

    @Override
    public Map<String, String> roleBasedUrls() {
        return Map.of("/admin", "ADMIN");
    }

    @Override
    public boolean csrfToken() {
        return true;
    }

    @Override
    public boolean isValidateToken() {
        return true; // Enable token validation
    }

    @Override
    public boolean enableOAuth() {
        return true;
    }
    // Example of creating tokens with different expiration times
    //public String defaultToken = createToken("yash"); // 30 minutes expiration
    //public String longLivedToken = createToken("yash", 60 * 24); // 24 hours expiration
    public String shortLivedToken = createToken("yash", 5); // 5 minutes expiration

    // Example of token validation
    public boolean validateUserToken(String token) {
        return validateToken(token, "yash");
    }

    // Example of extracting username from token
    public String getUsernameFromToken(String token) {
        return extractUsernameFromToken(token);
    }


}
