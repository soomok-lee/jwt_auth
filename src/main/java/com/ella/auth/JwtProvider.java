package com.ella.auth;

import io.jsonwebtoken.Claims;

public interface JwtProvider {

	public Claims getClaimsFromToken(String token); 
	public String getUsernameFromToken(String token);
	
	//ELLA TEST
	public String getNameFromToken(String token);
}
