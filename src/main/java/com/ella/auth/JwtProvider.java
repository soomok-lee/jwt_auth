package com.ella.auth;

import io.jsonwebtoken.Claims;

public interface JwtProvider {

	public Claims getClaimsFromValidatedToken(String token); 
	public String getUsernameFromToken(String token);
	
	public String getNameFromToken(String token);
}
