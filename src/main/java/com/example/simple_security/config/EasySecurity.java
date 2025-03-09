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

    @Autowired
    private JWTValidate jwtValidate;

    /*public urls*/
    private List<String> permittedUrls;

    /*authenticated urls*/
    private List<String> authenticatedUrls;

    /*role based urls*/
    private Map<String, String> roleBasedUrls;

    private boolean disableCsrfToken = false;

    private boolean enableOAuth = false;

    private boolean enableTokenValidation = false;

    @PostConstruct
    public void init(){
        this.permittedUrls=permittedUrls();
        this.authenticatedUrls=authenticatedUrls();
        this.roleBasedUrls=roleBasedUrls();
        this.disableCsrfToken=disableCsrfToken();
        this.enableOAuth=enableOAuth();
        this.enableTokenValidation=enableTokenValidation();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(auth ->{
                    permittedUrls.forEach(url -> auth.requestMatchers(url).permitAll());

                    authenticatedUrls.forEach(url -> auth.requestMatchers(url).authenticated());

                    roleBasedUrls.forEach((url,role) -> auth.requestMatchers(url).hasRole(role));

                    auth.anyRequest().authenticated();
                })
                .csrf(csrf -> {
                    if (disableCsrfToken()){
                        try{
                            csrf.disable();
                        }catch (Exception e){
                            logger.error("Unable to disable the csrf token "+e.getMessage());
                        }

                    }
                });
                if (enableTokenValidation()){
                    try{
                        httpSecurity.addFilterBefore(jwtValidate, UsernamePasswordAuthenticationFilter.class);
                    }catch (Exception e){
                        logger.error("Unable to launch token functionality "+e.getMessage());
                    }
                }
                if(enableOAuth()){
                    try {
                        httpSecurity.oauth2Login(Customizer.withDefaults());
                    } catch (Exception e){
                        logger.error("Unable to start Oauth please check application.properties "+e.getMessage());
                    }

                }
                httpSecurity.formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    public abstract List<String> permittedUrls();

    public abstract List<String> authenticatedUrls();

    public abstract Map<String, String> roleBasedUrls();

    public abstract boolean disableCsrfToken();

    /*Still need to enhance more cause default token validate for 30 min*/
    public String createToken(String username){
        return generateToken(username);
    }

    /*validate token but once you define it as true then you need to define the token methods*/
    public abstract boolean enableTokenValidation();

    /*for the Oauth enable but you need to define client id and client secret*/
    public abstract boolean enableOAuth();

    /**
     * Creates a JWT token with custom expiration time
     * @param username The username to create token for
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token
     */
    public String createToken(String username, long expirationMinutes) {
        if(expirationMinutes <= 0){
            logger.error("expiration time should not be zero or negative");
            throw new IllegalArgumentException("expiration time should not be zero or negative");
        }
        try{
            return generateToken(username, expirationMinutes);
        }catch (Exception e){
            throw new IllegalArgumentException("Unable to create token"+e.getMessage());
        }

    }


    /**
     * Validates a JWT token
     * @param token The JWT token to validate
     * @param username The username to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token, String username) {
        if(token==null || token.isEmpty() || username==null){
            logger.error("token and username should not be null or Empty");
            throw new IllegalArgumentException("token and username should not be null or Empty");
        }
        try{
            return super.validateToken(token, username);
        }catch (Exception e){
            throw new IllegalArgumentException("Unable to validate token "+e.getMessage());
        }

    }

    /**
     * Extracts username from a JWT token
     * @param token The JWT token
     * @return username if token is valid, null otherwise
     */
    public String extractUsernameFromToken(String token) {
        if(token == null || token.isEmpty()){
            logger.error("token should not be null or empty");
            throw new IllegalArgumentException("token should not be null or empty");
        }
        try {
            return extractUserName(token);
        }catch (Exception e){
            throw new IllegalArgumentException("Unable to extract token "+e.getMessage());
        }

    }

}
