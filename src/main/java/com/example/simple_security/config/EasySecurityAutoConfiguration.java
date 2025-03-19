package com.example.simple_security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Auto-configuration class for EasySecurity.
 * This ensures that users don't need to manually add @ComponentScan.
 */
@Configuration
@ConditionalOnMissingBean(EasySecurity.class) // This automatically registers EasySecurity
public class EasySecurityAutoConfiguration {
    // This class is empty but ensures auto-configuration
}
