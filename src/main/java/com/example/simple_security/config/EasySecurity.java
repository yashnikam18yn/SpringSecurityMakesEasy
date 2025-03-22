package com.example.simple_security.config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Configuration
public abstract class EasySecurity extends JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(EasySecurity.class);

   @Autowired(required = false)
   private JWTValidate jwtValidate;


    private final List<String> permittedUrls;
    private final List<String> authenticatedUrls;
    private final Map<String, String> roleBasedUrls;
    private final boolean disableCsrfToken;
    private final boolean enableOAuth;
    private final boolean enableTokenValidation;

    private final boolean isCustomLoginPage;
    private final String customLoginPageUrl;
    private final String loginProcessingUrl;
    private final String successForwardUrl;

    protected EasySecurity() {
        this.permittedUrls=safeList(permittedUrls());
        this.authenticatedUrls=safeList(authenticatedUrls());
        this.roleBasedUrls=safeMap(roleBasedUrls());
        this.disableCsrfToken=disableCsrfToken();
        this.enableOAuth=enableOAuth();
        this.enableTokenValidation=enableTokenValidation();
        this.isCustomLoginPage=isCustomLoginPage();
        this.customLoginPageUrl=customLoginPageUrl();
        this.loginProcessingUrl=loginProcessingUrl();
        this.successForwardUrl=successForwardUrl();

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
            try{
                httpSecurity.oauth2Login(Customizer.withDefaults());
            }catch (Exception e){
                logger.error("Unable to start oauth please check application.properties: "+e.getMessage());
            }
        }

        if(this.isCustomLoginPage()){
            try{
                httpSecurity.formLogin(form ->
                        form.loginPage(this.customLoginPageUrl())
                                .loginProcessingUrl(this.loginProcessingUrl())
                                .defaultSuccessUrl(this.successForwardUrl(),true)
                                .permitAll()
                        );
            }catch (Exception e){
                logger.error("Error configuration from login: "+ e.getMessage());
            }
        }else {
            try{
                httpSecurity.formLogin(Customizer.withDefaults());
            }catch (Exception e){
                logger.error("Error configuring default form login: "+e.getMessage());
            }
        }

        return httpSecurity.build();
    }

    private List<String> safeList(List<String> list) {
        return (list != null) ? list : Collections.emptyList();
    }

    private Map<String, String> safeMap(Map<String, String> map) {
        return (map != null) ? map : Collections.emptyMap();
    }

    //return the list of permitted urls
    public abstract List<String> permittedUrls();

    //return the list of authenticated urls
    public abstract List<String> authenticatedUrls();

    //return the key pair of url and role
    public abstract Map<String, String> roleBasedUrls();


    public abstract boolean disableCsrfToken();
    public abstract boolean enableTokenValidation();
    public abstract boolean enableOAuth();

    public abstract boolean isCustomLoginPage();
    public abstract String customLoginPageUrl();
    public abstract String loginProcessingUrl();
    public abstract String successForwardUrl();

    public String createToken(String username) {
        return generateToken(username);
    }




    /**
     * Creates a JWT token with custom expiration time
     * @param username The username to create token for
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token
     */
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



    /**
     * Validates a JWT token
     * @param token The JWT token to validate
     * @param username The username to validate against
     * @return true if token is valid, false otherwise
     */
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


    /**
     * Extracts username from a JWT token
     * @param token The JWT token
     * @return username if token is valid, null otherwise
     */
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

