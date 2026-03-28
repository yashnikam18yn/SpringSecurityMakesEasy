# 🔐 JWT Usage

## Enable JWT

```java
@Override
public boolean enableTokenValidation() {
    return true;
}
```

---

## Generate Token

```java
String token = webSecurity.createToken("username");
```

---

## Validate Token

```java
boolean isValid = webSecurity.validateToken(token, "username");
```

---

## Extract Username

```java
String username = webSecurity.extractUsernameFromToken(token);
```
