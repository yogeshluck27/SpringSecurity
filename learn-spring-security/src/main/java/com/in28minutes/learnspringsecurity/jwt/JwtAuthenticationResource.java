package com.in28minutes.learnspringsecurity.jwt;

import java.time.Instant;

import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//This Class is creating JWT & encoding it using JWT Encoder
//Step 1 : Use Basic Auth for Generating JWT Token
//Step 2 : Use JwT token as bearer Token for Authenticating requests
//@RestController
public class JwtAuthenticationResource {
	//This is used to Encode JWT 
	private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) { 
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate") 
	public JwtRespose authenticate(Authentication authentication) {
		return new JwtRespose(createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		JwtClaimsSet claims = JwtClaimsSet.builder()
								.issuer("self")
								.issuedAt(Instant.now())
								.expiresAt(Instant.now().plusSeconds(60 * 30))
								.subject(authentication.getName())
								.claim("scope", createScope(authentication))
								.build();
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims))
						.getTokenValue();
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority())
			.collect(Collectors.joining(" "));			
	}

}

class JwtRespose {
	String token;

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public JwtRespose(String token) {
		super();
		this.token = token;
	}
	
}
