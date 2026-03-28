package com.example.simple_security.config;

/**
 * Defines the HTTP session creation policy for EasySecurity.
 *
 * <pre>{@code
 * @Override
 * public SessionPolicy sessionPolicy() {
 *     return SessionPolicy.STATELESS; // for REST APIs with JWT
 * }
 * }</pre>
 */
public enum SessionPolicy {

    /** No session is created or used. Recommended for REST APIs using JWT. */
    STATELESS,

    /** A session is created only if required. Default Spring Security behaviour. */
    IF_REQUIRED,

    /** A session is never created but will be used if one already exists. */
    NEVER,

    /** A session is always created on every request. */
    ALWAYS
}