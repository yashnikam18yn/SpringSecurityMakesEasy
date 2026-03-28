package com.example.simple_security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTValidate extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTValidate.class);

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;

    // Both properly injected via constructor — no nulls possible
    public JWTValidate(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // No token — pass the request through, Spring Security handles the rest
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        // Malformed or expired token — extractUserName returns null
        final String username = jwtUtils.extractUserName(jwt);
        if (username == null) {
            logger.warn("[EasySecurity] JWT token is invalid or expired. Request: {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        // Only set authentication if not already set in this request
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtUtils.validateToken(jwt, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    logger.debug("[EasySecurity] Authenticated user '{}' via JWT.", username);
                }
            } catch (Exception e) {
                // Don't crash the filter chain — just log and let Spring Security reject it
                logger.error("[EasySecurity] Failed to authenticate user '{}': {}", username, e.getMessage());
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}