package com.example.simple_security.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;
import java.util.Map;

@Configuration
public abstract class EasySecurity extends JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(EasySecurity.class);

    @Autowired(required = true)
    private JWTValidate jwtValidate;

    private List<String> permittedUrls;
    private List<String> authenticatedUrls;
    private Map<String, String> roleBasedUrls;
    private boolean disableCsrfToken = false;
    private boolean enableOAuth = false;
    private boolean enableTokenValidation = false;

    @PostConstruct
    public void init() {
        this.permittedUrls = permittedUrls();
        this.authenticatedUrls = authenticatedUrls();
        this.roleBasedUrls = roleBasedUrls();
        this.disableCsrfToken = disableCsrfToken();
        this.enableOAuth = enableOAuth();
        this.enableTokenValidation = enableTokenValidation();

        if (enableTokenValidation && jwtValidate == null) {
            logger.warn("Token validation is enabled, but JWTValidate bean is missing. Token validation will not work.");
        }
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(auth -> {
                    permittedUrls.forEach(url -> auth.requestMatchers(url).permitAll());
                    authenticatedUrls.forEach(url -> auth.requestMatchers(url).authenticated());
                    roleBasedUrls.forEach((url, role) -> auth.requestMatchers(url).hasRole(role));
                    auth.anyRequest().authenticated();
                })
                .csrf(csrf -> {
                    if (disableCsrfToken) {
                        csrf.disable();
                    }
                });

        if (enableTokenValidation) {
            if (jwtValidate != null) {
                httpSecurity.addFilterBefore(jwtValidate, UsernamePasswordAuthenticationFilter.class);
            } else {
                logger.error("JWTValidate bean is missing. Cannot add JWT validation filter.");
            }
        }

        if (enableOAuth) {
            httpSecurity.oauth2Login(Customizer.withDefaults());
        }

        httpSecurity.formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    public abstract List<String> permittedUrls();
    public abstract List<String> authenticatedUrls();
    public abstract Map<String, String> roleBasedUrls();
    public abstract boolean disableCsrfToken();
    public abstract boolean enableTokenValidation();
    public abstract boolean enableOAuth();

    public String createToken(String username) {
        return generateToken(username);
    }

    public String createToken(String username, long expirationMinutes) {
        if (expirationMinutes <= 0) {
            logger.error("Expiration time should not be zero or negative.");
            throw new IllegalArgumentException("Expiration time should not be zero or negative.");
        }
        try {
            return generateToken(username, expirationMinutes);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to create token: " + e.getMessage());
        }
    }

    public boolean validateToken(String token, String username) {
        if (token == null || token.isEmpty() || username == null) {
            logger.error("Token and username should not be null or empty.");
            throw new IllegalArgumentException("Token and username should not be null or empty.");
        }
        try {
            return super.validateToken(token, username);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to validate token: " + e.getMessage());
        }
    }

    public String extractUsernameFromToken(String token) {
        if (token == null || token.isEmpty()) {
            logger.error("Token should not be null or empty.");
            throw new IllegalArgumentException("Token should not be null or empty.");
        }
        try {
            return extractUserName(token);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to extract username from token: " + e.getMessage());
        }
    }
}

