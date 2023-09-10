package com.isteer.spring.security;

import java.security.Principal;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.isteer.dao.UserDao;
import com.isteer.jwt.token.AccessDeniedEntryPoint;
import com.isteer.jwt.token.CustomBearerTokenExceptionEntryPoint;
import com.isteer.jwt.token.JwtFilter;
import com.isteer.module.EndPoint;

@Configuration
@EnableWebSecurity
public class SpringSecurity {

	private final UserDetailsService userDetailsService;
	private final JwtFilter jwtFilter;
	private final CustomBearerTokenExceptionEntryPoint customBearerTokenExceptionEntryPoint;
	private final AccessDeniedEntryPoint accessDeniedEntryPoint;
	private final UserDao dao;

	public SpringSecurity(UserDetailsService userDetailsService, JwtFilter jwtFilter,
			CustomBearerTokenExceptionEntryPoint customBearerTokenExceptionEntryPoint,
			AccessDeniedEntryPoint accessDeniedEntryPoint, UserDao dao) {
		this.userDetailsService = userDetailsService;
		this.jwtFilter = jwtFilter;
		this.customBearerTokenExceptionEntryPoint = customBearerTokenExceptionEntryPoint;
		this.accessDeniedEntryPoint = accessDeniedEntryPoint;
		this.dao = dao;
	}

	@Bean
	public PasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf(csr -> csr.disable());
		List<EndPoint> endPoints = dao.getAllEndPointDetails();
		for (EndPoint endPoint : endPoints) {
			if (endPoint.getAuthorities().contains("PermitAll")) {
				httpSecurity.authorizeHttpRequests(
						request -> request.requestMatchers(endPoint.getEndPointName()).permitAll());
			} else {
				String[] authority = endPoint.getAuthorities().stream().toArray(String[]::new);
				httpSecurity.authorizeHttpRequests(
						request -> request.requestMatchers(endPoint.getEndPointName()).hasAnyAuthority(authority));
			}
		}
		httpSecurity.authorizeHttpRequests(request -> request.anyRequest().permitAll());
		httpSecurity
				.exceptionHandling(exp -> exp.authenticationEntryPoint(customBearerTokenExceptionEntryPoint)
						.accessDeniedHandler(accessDeniedEntryPoint))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		httpSecurity.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		return httpSecurity.build();
	}

	@Bean
	public AuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

}
