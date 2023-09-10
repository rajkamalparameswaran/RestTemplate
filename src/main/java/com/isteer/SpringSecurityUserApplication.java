package com.isteer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication

public class SpringSecurityUserApplication {
	private static final Logger AUDITLOG = LogManager.getLogger(SpringSecurityUserApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityUserApplication.class, args);
		AUDITLOG.info("Application started sucessfully");
	}

}
