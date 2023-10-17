package com.in28minutes.learnoauth;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
//https://docs.spring.io/spring-security-oauth2-boot/docs/2.2.0.M3/reference/html/boot-features-security-oauth2-authorization-server.html
@Configuration
public class OauthSecurityConfiguration {

	@Bean
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests().anyRequest().authenticated();
		//http.formLogin();
		//http.httpBasic();
		http.oauth2Login(Customizer.withDefaults());
		return http.build();
	}

}
