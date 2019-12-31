package com.ella.auth;

import io.jsonwebtoken.Claims;

public class JwtClaims {

	public Claims claims;

	public Claims getClaims() {
		return claims;
	}

	public void setClaims(Claims claims) {
		this.claims = claims;
	}
	
}
