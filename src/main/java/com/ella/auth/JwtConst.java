package com.ella.auth;

import io.jsonwebtoken.SignatureAlgorithm;

public interface JwtConst {

	public static final String TOKEN_PREFIX = "Token ";   
	public static final String BEARER_PREFIX = "Bearer ";
    public static final String SHD_TOKEN_KEY = "Authorization";      
    
    public static final String ID = "id";
    public static final String NAME = "name";
    public static final String AUTHORITIES_KEY = "roles";

    default public int getIatTTLSeconds() { //FIXME 일단 default method로 처리 
    	return 3600;
    };
    
    default public String getSigningKey(String issuer) { //FIXME 일단 default method로 처리 
    	return "set your signingKey";
    }; 
    
    default public SignatureAlgorithm getSignatureAlgorithm() { //FIXME 일단 default method로 처리 
    	SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    	return signatureAlgorithm;
    };
}
