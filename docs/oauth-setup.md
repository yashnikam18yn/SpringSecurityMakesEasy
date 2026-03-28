# 🌐 OAuth2 Setup

## Enable OAuth

```java
@Override
public boolean enableOAuth() {
    return true;
}
```

---

## application.properties

```properties
spring.security.oauth2.client.registration.google.client-id=YOUR_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_SECRET
```
