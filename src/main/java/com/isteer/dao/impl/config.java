package com.isteer.dao.impl;

import java.security.Principal;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
public class config {
	
	@Bean
	public Principal getPrincipal() {
		return () -> SecurityContextHolder.getContext().getAuthentication().getName();
	}

}
