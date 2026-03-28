# 🌍 CORS Configuration

```java
@Override
public EasyCorsConfiguration corsConfiguration() {
    return new EasyCorsConfiguration()
        .allowedOrigins(List.of("http://localhost:3000"))
        .allowedMethods(List.of("GET", "POST", "PUT", "DELETE"))
        .allowedHeaders(List.of("*"))
        .allowCredentials(true);
}
```
