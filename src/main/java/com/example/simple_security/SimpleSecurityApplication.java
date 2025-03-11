package com.example.simple_security;

import com.example.simple_security.config.EasySecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.example")
public class SimpleSecurityApplication {

	public static void main(String[] args) {

		SpringApplication.run(SimpleSecurityApplication.class, args);

	}

}
