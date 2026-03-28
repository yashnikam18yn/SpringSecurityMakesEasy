# 🔐 Spring Security Makes Easy

A lightweight framework built on top of Spring Security to simplify authentication and authorization with minimal configuration.

---

## 🚀 What's New in v1.2.0

- ✅ Configurable JWT secret via `application.properties`
- ✅ CORS configuration support (`EasyCorsConfiguration`)
- ✅ Session management support:
  - STATELESS
  - IF_REQUIRED
  - NEVER
  - ALWAYS
- 🐛 Fixed `NullPointerException` in JWT validation
- 🐛 Refactored `EasySecurity` (Inheritance → Composition)

---

## ✨ Features

- 🔑 **Easy URL Permissions** – Quickly allow/deny routes
- 👥 **Role-Based Access Control** – Restrict access by roles
- 🔐 **JWT Authentication & Validation** – Simplified token security
- 🌍 **OAuth2 Login** – Google, GitHub, and more
- 🛡 **API Protection** – Secure endpoints easily
- 🔧 **Customizable Security** – Extend as per your needs
- 📄 **Pre-Built Methods** – Reduce boilerplate code

---

🔗 Maven Central

👉 https://central.sonatype.com/artifact/io.github.yashnikam18yn/spring-security-makes-easy/1.2.0

## 📦 Installation

Add the dependency:

```xml
<dependency>
    <groupId>io.github.yashnikam18yn</groupId>
    <artifactId>spring-security-makes-easy</artifactId>
    <version>1.2.0</version>
</dependency>


