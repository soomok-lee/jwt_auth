package com.ella.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultHeader;

public class JwtClaims {
	
	public DefaultHeader<?> headerClaims;
	public Claims bodyClaims;
	
	public DefaultHeader<?> getHeaderClaims() {
		return headerClaims;
	}
	public void setHeaderClaims(DefaultHeader<?> headerClaims) {
		this.headerClaims = headerClaims;
	}
	
	public Claims getBodyClaims() {
		return bodyClaims;
	}
	public void setBodyClaims(Claims bodyClaims) {
		this.bodyClaims = bodyClaims;
	}

}
