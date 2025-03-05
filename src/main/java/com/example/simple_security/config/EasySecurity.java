package com.example.simple_security.config;

import jakarta.annotation.PostConstruct;
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

    @Autowired
    private JWTValidate jwtValidate;

    /*public urls*/
    private List<String> permittedUrls;

    /*authenticated urls*/
    private List<String> authenticatedUrls;


    /*role based urls*/
    private Map<String, String> roleBasedUrls;

    private boolean csrfToken = false;

    private boolean enableOAuth = false;

    private boolean isValidateToken = false;

    @PostConstruct
    public void init(){
        this.permittedUrls=permittedUrls();
        this.authenticatedUrls=authenticatedUrls();
        this.roleBasedUrls=roleBasedUrls();
        this.csrfToken=csrfToken();
        this.enableOAuth=enableOAuth();
        this.isValidateToken=isValidateToken();
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
                    if (csrfToken()){
                        csrf.disable();
                    }
                });
                if (isValidateToken()){
                    httpSecurity.addFilterBefore(jwtValidate, UsernamePasswordAuthenticationFilter.class);
                }
                if(enableOAuth()){
                    httpSecurity.oauth2Login(Customizer.withDefaults());
                }
                httpSecurity.formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    public abstract List<String> permittedUrls();

    public abstract List<String> authenticatedUrls();

    public abstract Map<String, String> roleBasedUrls();

    public abstract boolean csrfToken();

    //public abstract String generateToken(String username);


    /*Still need to enhance more cause default token validate for 30 min*/
    public String createToken(String username){
        return generateToken(username);
    }


    /*validate token*/
    public abstract boolean isValidateToken();


    /*for the Oauth enable*/
    public abstract boolean enableOAuth();

    /**
     * Creates a JWT token with custom expiration time
     * @param username The username to create token for
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token
     */
    public String createToken(String username, long expirationMinutes) {
        return generateToken(username, expirationMinutes);
    }

    /**
     * Validates a JWT token
     * @param token The JWT token to validate
     * @param username The username to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token, String username) {
        return super.validateToken(token, username);
    }

    /**
     * Extracts username from a JWT token
     * @param token The JWT token
     * @return username if token is valid, null otherwise
     */
    public String extractUsernameFromToken(String token) {
        return extractUserName(token);
    }
}
