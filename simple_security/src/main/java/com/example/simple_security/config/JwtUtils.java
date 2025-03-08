package com.example.simple_security.config;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.io.Decoders;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

// here only generate the token

@Component
public class JwtUtils {

    private String sk = ""; // key to use the generate token
    private static final long DEFAULT_EXPIRATION_MINUTES = 30;

    public JwtUtils() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            sk = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize JWT key generator", e);
        }
    }

    // Function which generates token with default expiration
    protected String generateToken(String username) {
        return generateToken(username, DEFAULT_EXPIRATION_MINUTES);
    }

    // Function which generates token with custom expiration
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

    // Generate key for signWith
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(sk);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Extract username from token
    public String extractUserName(String token) {
        try {
            return Jwts.parser().verifyWith((SecretKey) getKey()).build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (JwtException e) {
            return null;
        }
    }

    // Validate token
    public boolean validateToken(String token, String username) {
        try {
            String extractedUsername = extractUserName(token);
            return extractedUsername != null &&
                    extractedUsername.equals(username) &&
                    !isTokenExpired(token);
        } catch (JwtException e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        try {
            Date expiration = Jwts.parser().verifyWith((SecretKey) getKey()).build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();
            return expiration.before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }
}
