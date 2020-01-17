package com.ella.auth;

public interface JwtGenerator {
	
	public String generateJWT(String id, String issuer, String subject, String roles);
	
}
