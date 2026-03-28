package com.example.simple_security.config;

import java.util.List;

public class EasyCorsConfiguration {

    private List<String> allowedOrigins = List.of("*");
    private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
    private List<String> allowedHeaders = List.of("*");
    private boolean allowCredentials    = false;
    private long maxAge                 = 3600L;

    /**
     * Origins allowed to make cross-origin requests.
     * Use {@code List.of("*")} to allow all (development only).
     * When {@link #allowCredentials(boolean)} is {@code true}, wildcards are not permitted —
     * you must specify explicit origins.
     * <pre>{@code
     * .allowedOrigins(List.of("https://myfrontend.com", "http://localhost:3000"))
     * }</pre>
     *
     * @param allowedOrigins list of allowed origin URLs
     * @return this instance for chaining
     */
    public EasyCorsConfiguration allowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
        return this;
    }

    /**
     * HTTP methods allowed for cross-origin requests.
     * <pre>{@code
     * .allowedMethods(List.of("GET", "POST", "PUT", "DELETE"))
     * }</pre>
     *
     * @param allowedMethods list of HTTP method names
     * @return this instance for chaining
     */
    public EasyCorsConfiguration allowedMethods(List<String> allowedMethods) {
        this.allowedMethods = allowedMethods;
        return this;
    }

    /**
     * Request headers allowed in cross-origin requests.
     * Use {@code List.of("*")} to allow all headers.
     * <pre>{@code
     * .allowedHeaders(List.of("Authorization", "Content-Type"))
     * }</pre>
     *
     * @param allowedHeaders list of allowed header names
     * @return this instance for chaining
     */
    public EasyCorsConfiguration allowedHeaders(List<String> allowedHeaders) {
        this.allowedHeaders = allowedHeaders;
        return this;
    }

    /**
     * Whether to allow cookies and Authorization headers in cross-origin requests.
     * When {@code true}, {@link #allowedOrigins} must contain explicit origins — not {@code "*"}.
     *
     * @param allowCredentials {@code true} to allow credentials, {@code false} to deny
     * @return this instance for chaining
     */
    public EasyCorsConfiguration allowCredentials(boolean allowCredentials) {
        this.allowCredentials = allowCredentials;
        return this;
    }

    /**
     * How long (in seconds) the browser should cache the preflight response.
     * Default is {@code 3600} (1 hour).
     *
     * @param maxAge duration in seconds
     * @return this instance for chaining
     */
    public EasyCorsConfiguration maxAge(long maxAge) {
        this.maxAge = maxAge;
        return this;
    }

    // ─── Getters (used internally by EasySecurity) ────────────────────────────

    public List<String> getAllowedOrigins()  { return allowedOrigins; }
    public List<String> getAllowedMethods()  { return allowedMethods; }
    public List<String> getAllowedHeaders()  { return allowedHeaders; }
    public boolean isAllowCredentials()      { return allowCredentials; }
    public long getMaxAge()                  { return maxAge; }
}