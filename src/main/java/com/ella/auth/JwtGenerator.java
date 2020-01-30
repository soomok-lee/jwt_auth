package com.ella.auth;

import java.util.Map;

public interface JwtGenerator {
	
	public String generateJWT(String issuer, String subject, Long expMillis, Map<String,String> claims);

	public String generateJWTWithKey(String issuer, String subject, Long expMillis, Map<String, String> claims,	String signingKey);
	
}
