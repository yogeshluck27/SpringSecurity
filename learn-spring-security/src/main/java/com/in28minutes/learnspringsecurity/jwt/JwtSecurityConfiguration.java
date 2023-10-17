package com.in28minutes.learnspringsecurity.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//This class is used to validate the JWT 
//First 4 steps are used to validate / decode 
//5th step is JWT Encode which is used while creating JWT
//@Configuration
public class JwtSecurityConfiguration {
	//All Request are authenticated using below code
	//It like AuthenticationManager which uses JWT Auth Provider & UserDetails Service to fetch user data
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
						auth -> {
							auth.anyRequest().authenticated();
						});
		
		http.sessionManagement(
						session -> 
							session.sessionCreationPolicy(
									SessionCreationPolicy.STATELESS)
						);
		
		http.httpBasic();
		
		http.csrf().disable();
		
		http.headers().frameOptions().sameOrigin();
		//This is added for configuring JWT
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		
		
		return http.build();
	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	//while creating JWT we use /authenticate Resource
	//We provide Basic Auth to create JWT which is combination of username & password 
	//This username & password is stored in Database
	//Password is hashed using BCryptPasswordEncoder
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		UserDetails user = User.withUsername("in28minutes")
			//.password("{noop}dummy")
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();
		
		UserDetails admin = User.withUsername("admin")
				//.password("{noop}dummy")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN", "USER")
				.build();
		
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	//1st step in jwt flow is to create key pair
	@Bean
	public KeyPair keyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	//2nd step : Create RSA Key Object using KeyPair
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		
		return new RSAKey
				.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}
	//3rd step: Create JWKSource using JWTSet. JWKSet can consist of multiple rsaKeys.
	//Here we are using only one Key.
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		JWKSet jwkSet = new JWKSet(rsaKey);
		
		return (jwkSelector, context) ->  jwkSelector.select(jwkSet);
		
	}
	//4th Step : Create RSA Public Key for Decoding. So create JWtDecoder using RSA Key
	//This is used by Resource Server to validate JWT
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
		
	}
	//5th Step : Create JWT Encoder using jwkSource //This is to Encode JWT. To be used in JwtAuthentication
	//Resource while creating JWT
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}










