package com.example.simple_security.config;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final String sk;
    private final long defaultExpirationMinutes;

    @Autowired
    public JwtUtils(EasySecurityProperties properties) {
        String configuredSecret = properties.getJwt().getSecret();
        this.defaultExpirationMinutes = properties.getJwt().getExpiration();

        if (configuredSecret != null && !configuredSecret.isBlank()) {
            // Validate minimum key length (HMAC-SHA256 needs >= 256 bits = 32 bytes)
            byte[] keyBytes = configuredSecret.getBytes();
            if (keyBytes.length < 32) {
                throw new IllegalArgumentException(
                        "[EasySecurity] easysecurity.jwt.secret must be at least 32 characters long."
                );
            }
            this.sk = Base64.getEncoder().encodeToString(keyBytes);
            logger.info("[EasySecurity] JWT secret loaded from application.properties.");
        } else {
            // Auto-generate — warn the developer clearly
            this.sk = generateRandomSecret();
            logger.warn("[EasySecurity] No JWT secret configured. A random secret has been generated.");
            logger.warn("[EasySecurity] All tokens will be invalidated on every application restart.");
            logger.warn("[EasySecurity] Set 'easysecurity.jwt.secret=your-secret' in application.properties to fix this.");
        }
    }

    private String generateRandomSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("[EasySecurity] Failed to generate JWT secret key", e);
        }
    }

    protected String generateToken(String username) {
        return generateToken(username, defaultExpirationMinutes);
    }

    protected String generateToken(String username, long expirationMinutes) {
        Date now = new Date(System.currentTimeMillis());
        Date expiration = new Date(now.getTime() + expirationMinutes * 60 * 1000);

        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getKey())
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(sk);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        try {
            return Jwts.parser()
                    .verifyWith((SecretKey) getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (JwtException e) {
            return null;
        }
    }

    public boolean validateToken(String token, String username) {
        try {
            String extractedUsername = extractUserName(token);
            return extractedUsername != null
                    && extractedUsername.equals(username)
                    && !isTokenExpired(token);
        } catch (JwtException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            Date expiration = Jwts.parser()
                    .verifyWith((SecretKey) getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();
            return expiration.before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }
}