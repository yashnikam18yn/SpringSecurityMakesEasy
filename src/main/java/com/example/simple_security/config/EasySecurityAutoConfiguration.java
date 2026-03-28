package com.example.simple_security.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@ConditionalOnMissingBean(EasySecurity.class)
public class EasySecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EasySecurityProperties easySecurityProperties(Environment environment) {
        return Binder.get(environment)
                .bindOrCreate("easysecurity", EasySecurityProperties.class);
    }
}