package com.example.simple_security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(EasySecurityProperties.class)
@ConditionalOnMissingBean(EasySecurity.class)
public class EasySecurityAutoConfiguration {
}