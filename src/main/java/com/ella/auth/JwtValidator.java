package com.ella.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultHeader;

public interface JwtValidator {

	public Boolean validateToken(String token);
	
	public DefaultHeader<?> getHeaderClaimsFromToken(String token);
	public Claims getBodyClaimsFromToken(String token); 
	
	public JwtClaims getAllClaimsFromToken(String token);

}
