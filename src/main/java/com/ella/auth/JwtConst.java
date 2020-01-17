package com.ella.auth;

public interface JwtConst {

	public static final String TOKEN_PREFIX = "Token ";   
	public static final String BEARER_PREFIX = "Bearer ";
    public static final String SHD_TOKEN_KEY = "Authorization";      

    public static final String ID = "id";
    public static final String NAME = "name";
    public static final String AUTHORITIES_KEY = "roles";

    public String getSigningKey(String issuer);
}
