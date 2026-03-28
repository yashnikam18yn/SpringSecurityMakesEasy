package com.example.simple_security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "easysecurity")
public class EasySecurityProperties {

    private Jwt jwt = new Jwt();

    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }

    public static class Jwt {
        private String secret = "";           // empty = auto-generate
        private long expiration = 30;         // minutes, default 30

        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }

        public long getExpiration() { return expiration; }
        public void setExpiration(long expiration) { this.expiration = expiration; }
    }
}