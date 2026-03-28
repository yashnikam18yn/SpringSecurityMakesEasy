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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.config.http.SessionCreationPolicy;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Configuration
public abstract class EasySecurity {

    private static final Logger logger = LoggerFactory.getLogger(EasySecurity.class);

    @Autowired
    private JwtUtils jwtUtils;

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
        this.permittedUrls         = safeList(permittedUrls());
        this.authenticatedUrls     = safeList(authenticatedUrls());
        this.roleBasedUrls         = safeMap(roleBasedUrls());
        this.disableCsrfToken      = disableCsrfToken();
        this.enableOAuth           = enableOAuth();
        this.enableTokenValidation = enableTokenValidation();
        this.isCustomLoginPage     = isCustomLoginPage();
        this.customLoginPageUrl    = customLoginPageUrl();
        this.loginProcessingUrl    = loginProcessingUrl();
        this.successForwardUrl     = successForwardUrl();
    }

    private SessionCreationPolicy resolveSessionPolicy() {
        return switch (sessionPolicy()) {
            case STATELESS   -> SessionCreationPolicy.STATELESS;
            case IF_REQUIRED -> SessionCreationPolicy.IF_REQUIRED;
            case NEVER       -> SessionCreationPolicy.NEVER;
            case ALWAYS      -> SessionCreationPolicy.ALWAYS;
        };
    }

    // ─── Security Filter Chain ────────────────────────────────────────────────

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        // CORS
        EasyCorsConfiguration easyCors = corsConfiguration();
        if (easyCors != null) {
            httpSecurity.cors(cors -> cors.configurationSource(buildCorsConfigurationSource(easyCors)));
            logger.info("[EasySecurity] CORS configured. Allowed origins: {}", easyCors.getAllowedOrigins());
        } else {
            logger.info("[EasySecurity] CORS not configured. Override corsConfiguration() to enable it.");
        }

        // Authorization & CSRF
        httpSecurity
                .authorizeHttpRequests(auth -> {
                    permittedUrls.forEach(url -> auth.requestMatchers(url).permitAll());
                    authenticatedUrls.forEach(url -> auth.requestMatchers(url).authenticated());
                    roleBasedUrls.forEach((url, role) -> auth.requestMatchers(url).hasRole(role));
                    auth.anyRequest().authenticated();
                })
                .csrf(csrf -> {
                    if (disableCsrfToken) csrf.disable();
                });
        // Session Management
        httpSecurity.sessionManagement(session ->
                session.sessionCreationPolicy(resolveSessionPolicy())
        );
        logger.info("[EasySecurity] Session policy set to: {}", sessionPolicy());

        // JWT Filter
        if (enableTokenValidation) {
            if (jwtValidate != null) {
                httpSecurity.addFilterBefore(jwtValidate, UsernamePasswordAuthenticationFilter.class);
            } else {
                logger.error("[EasySecurity] enableTokenValidation=true but JWTValidate bean is missing. " +
                        "Make sure you have a UserDetailsService bean in your application context.");
            }
        }

        // OAuth2
        if (enableOAuth) {
            try {
                httpSecurity.oauth2Login(Customizer.withDefaults());
            } catch (Exception e) {
                logger.error("[EasySecurity] OAuth2 setup failed. Check your application.properties: {}", e.getMessage());
            }
        }

        // Form Login
        if (isCustomLoginPage) {
            try {
                httpSecurity.formLogin(form ->
                        form.loginPage(customLoginPageUrl)
                                .loginProcessingUrl(loginProcessingUrl)
                                .defaultSuccessUrl(successForwardUrl, true)
                                .permitAll()
                );
            } catch (Exception e) {
                logger.error("[EasySecurity] Custom login page configuration failed: {}", e.getMessage());
            }
        } else {
            try {
                httpSecurity.formLogin(Customizer.withDefaults());
            } catch (Exception e) {
                logger.error("[EasySecurity] Default form login configuration failed: {}", e.getMessage());
            }
        }

        return httpSecurity.build();
    }

    /**
     * Session management policy for this application.
     * Defaults to {@link SessionPolicy#STATELESS} — recommended for REST APIs using JWT.
     * Override only if you need session-based authentication.
     * <pre>{@code
     * // Stateless — JWT (default, no need to override)
     * return SessionPolicy.STATELESS;
     *
     * // Stateful — traditional form login with sessions
     * return SessionPolicy.IF_REQUIRED;
     * }</pre>
     *
     * @return the {@link SessionPolicy} to apply
     */
    public SessionPolicy sessionPolicy() {
        return SessionPolicy.STATELESS;
    }

    // ─── CORS Internal Builder ────────────────────────────────────────────────

    private CorsConfigurationSource buildCorsConfigurationSource(EasyCorsConfiguration easyCors) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(easyCors.getAllowedOrigins());
        config.setAllowedMethods(easyCors.getAllowedMethods());
        config.setAllowedHeaders(easyCors.getAllowedHeaders());
        config.setAllowCredentials(easyCors.isAllowCredentials());
        config.setMaxAge(easyCors.getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // ─── JWT Utilities ────────────────────────────────────────────────────────

    public String createToken(String username) {
        return jwtUtils.generateToken(username);
    }

    public String createToken(String username, long expirationMinutes) {
        if (expirationMinutes <= 0) {
            throw new IllegalArgumentException("[EasySecurity] Expiration time must be greater than zero.");
        }
        return jwtUtils.generateToken(username, expirationMinutes);
    }

    public boolean validateToken(String token, String username) {
        if (token == null || token.isBlank() || username == null) {
            throw new IllegalArgumentException("[EasySecurity] Token and username must not be null or empty.");
        }
        return jwtUtils.validateToken(token, username);
    }

    public String extractUsernameFromToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("[EasySecurity] Token must not be null or empty.");
        }
        return jwtUtils.extractUserName(token);
    }

    // ─── Abstract Methods (override these in your config class) ──────────────

    /**
     * URLs that are publicly accessible without authentication.
     * <pre>{@code
     * return List.of("/api/auth/**", "/public/**");
     * }</pre>
     *
     * @return list of permitted URL patterns, or empty list if none
     */
    public abstract List<String> permittedUrls();

    /**
     * URLs that require the user to be authenticated (any role).
     * <pre>{@code
     * return List.of("/api/profile/**", "/api/orders/**");
     * }</pre>
     *
     * @return list of authenticated URL patterns, or empty list if none
     */
    public abstract List<String> authenticatedUrls();

    /**
     * Map of URL pattern to required role. Role names without the {@code ROLE_} prefix.
     * <pre>{@code
     * return Map.of(
     *     "/api/admin/**", "ADMIN",
     *     "/api/reports/**", "MANAGER"
     * );
     * }</pre>
     *
     * @return map of URL to role, or empty map if none
     */
    public abstract Map<String, String> roleBasedUrls();

    /**
     * Set {@code true} to disable CSRF protection.
     * Recommended for stateless REST APIs using JWT.
     *
     * @return {@code true} to disable CSRF, {@code false} to keep it enabled
     */
    public abstract boolean disableCsrfToken();

    /**
     * Set {@code true} to enable JWT token validation on every request.
     * Requires a {@code UserDetailsService} bean in your application context.
     *
     * @return {@code true} to enable JWT validation, {@code false} to disable
     */
    public abstract boolean enableTokenValidation();

    /**
     * Set {@code true} to enable OAuth2 social login (Google, GitHub, etc.).
     * Requires OAuth2 client credentials in {@code application.properties}.
     * <pre>{@code
     * spring.security.oauth2.client.registration.google.client-id=YOUR_ID
     * spring.security.oauth2.client.registration.google.client-secret=YOUR_SECRET
     * }</pre>
     *
     * @return {@code true} to enable OAuth2 login, {@code false} to disable
     */
    public abstract boolean enableOAuth();

    /**
     * Set {@code true} to use a custom login page instead of Spring's default.
     * When {@code true}, also implement {@link #customLoginPageUrl()},
     * {@link #loginProcessingUrl()}, and {@link #successForwardUrl()}.
     *
     * @return {@code true} for custom login page, {@code false} for Spring's default
     */
    public abstract boolean isCustomLoginPage();

    /**
     * URL path of your custom login page.
     * Only used when {@link #isCustomLoginPage()} returns {@code true}.
     * <pre>{@code
     * return "/login";
     * }</pre>
     *
     * @return the login page URL path
     */
    public abstract String customLoginPageUrl();

    /**
     * URL that Spring Security listens on to process login form submissions.
     * Your HTML form's {@code action} attribute should point to this URL.
     * Only used when {@link #isCustomLoginPage()} returns {@code true}.
     * <pre>{@code
     * return "/login";
     * }</pre>
     *
     * @return the login processing URL path
     */
    public abstract String loginProcessingUrl();

    /**
     * URL to redirect the user to after a successful login.
     * Only used when {@link #isCustomLoginPage()} returns {@code true}.
     * <pre>{@code
     * return "/dashboard";
     * }</pre>
     *
     * @return the post-login redirect URL path
     */
    public abstract String successForwardUrl();

    /**
     * CORS configuration for cross-origin requests.
     * Return {@code null} to disable CORS entirely.
     * <pre>{@code
     * // Production — specific origins
     * return new EasyCorsConfiguration()
     *     .allowedOrigins(List.of("https://myfrontend.com", "http://localhost:3000"))
     *     .allowedMethods(List.of("GET", "POST", "PUT", "DELETE"))
     *     .allowedHeaders(List.of("Authorization", "Content-Type"))
     *     .allowCredentials(true);
     *
     * // Development — allow everything
     * return new EasyCorsConfiguration();
     *
     * // Disable CORS
     * return null;
     * }</pre>
     *
     * @return {@link EasyCorsConfiguration} instance, or {@code null} to skip CORS setup
     */
    public abstract EasyCorsConfiguration corsConfiguration();

    // ─── Internal Helpers ─────────────────────────────────────────────────────

    private List<String> safeList(List<String> list) {
        return list != null ? list : Collections.emptyList();
    }

    private Map<String, String> safeMap(Map<String, String> map) {
        return map != null ? map : Collections.emptyMap();
    }
}