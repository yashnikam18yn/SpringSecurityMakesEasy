# ⚙️ Configuration Guide

## Permitted URLs

```java
@Override
public List<String> permittedUrls() {
    return List.of("/api/auth/**");
}
```

---

## Authenticated URLs

```java
@Override
public List<String> authenticatedUrls() {
    return List.of("/api/user/**");
}
```

---

## Role-Based Access

```java
@Override
public Map<String, String> roleBasedUrls() {
    return Map.of("/api/admin/**", "ADMIN");
}
```

---

## Disable CSRF

```java
@Override
public boolean disableCsrfToken() {
    return true;
}
```
