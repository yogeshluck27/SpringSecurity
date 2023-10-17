package com.in28minutes.learnspringsecurity.basic;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//This class disables CSRF makes requests stateless

//Commenting this class as we are using JWT
@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true) //This is used for method level security
public class BasicAuthSecurityConfiguration {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
						auth -> {
							auth
							.antMatchers("/users").hasAnyRole("USER")
							.antMatchers("/admin/**").hasAnyRole("ADMIN")  //Global Security
							.anyRequest()
							.authenticated();
							
						});
		
		http.sessionManagement(
						session -> 
							session.sessionCreationPolicy(
									SessionCreationPolicy.STATELESS)
						);
		
		//http.formLogin();  //no form login
		http.httpBasic();
		http.headers().frameOptions().sameOrigin(); //to view h2 console 

		//http.csrf().disable();  //disable CSRF
		
		return http.build();
	}
	//Below code is related to in memonry database.You can comment user name & password in application.properties.
	
	/*@Bean
	public UserDetailsService userDetailService() {
		
		UserDetails user = User.withUsername("in28minutes")
			.password("{noop}dummy")
			.roles("USER")
			.build();

		
		UserDetails admin = User.withUsername("admin")
			.password("{noop}dummy")
				.roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user, admin);
	}*/
	
	//Below code of datasource will configure default schema in H2 Database
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	//Below code is to insert Username & password in H2 Database
	//Login to http://localhost:8080/h2-console use 'jdbc:h2:mem:testdb' as db url
	//which is configured in application.peroperties
	//USERS & AUTHORITIES tables are created with Data
	
	//Try to login http://localhost:8080/list-todos and put below configured username & password
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		UserDetails user = User.withUsername("in28minutes")
			//.password("{noop}dummy") //commented this line as we are using password encoder to store it in Db
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			//Check the password value in USERS table in H2 Database.It will be hash value 
			.roles("USER")
			.build();
		
		UserDetails admin = User.withUsername("admin")
				//.password("{noop}dummy") //commented this line as we are using password encoder to store it in Db
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				//Check the password value in USERS table in H2 Database.It will be hash value 
				.roles("ADMIN", "USER")
				.build();
		
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	//below is the bean which does hashing of password & store it in Db.
	//Its one way function we cannot getback password from hash value
	//Its not doing encoding ..its doing hashing
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
