package com.ella.auth;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtGeneratorImpl implements JwtGenerator{
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass()); // log 생성한 class 지정

	private JwtConst jwtConst;
	
	public JwtGeneratorImpl(JwtConst jwtConst) {
		super();
		this.jwtConst = jwtConst;
	}
	
	@Override
	public String generateJWT(String issuer, String subject, Long expMillis, Map<String, String> claims) {
		  
		logger.debug("generating JWT");
		
	    String uuid = UUID.randomUUID().toString();
	    long nowMillis = System.currentTimeMillis();
	    Date now = new Date(nowMillis);

	    String signingKey = jwtConst.getSigningKey(issuer);
	    
	    //Let's set the JWT Claims
	    JwtBuilder jwtBuilder = getJwtBuilder(signingKey);
		jwtBuilder.setId(uuid)
			.setIssuedAt(now)
			.setSubject(subject)
			.setIssuer(issuer);
		
		// ELLA claim(JwtConst.AUTHORITIES_KEY, roles) FOREACH
		for (Map.Entry<String, String> entry : claims.entrySet()) {
			jwtBuilder.claim(entry.getKey(), entry.getValue());
		}
		
		// if it has been specified, let's add the expiration
	    if(expMillis != null) {
			expMillis = nowMillis + expMillis;
			Date exp = new Date(expMillis);
			jwtBuilder.setExpiration(exp);
		}
	    
	    //Builds the JWT and serializes it to a compact, URL-safe string
	    return jwtBuilder.compact();
	}
	
	@Override
	public String generateJWTWithKey(String issuer, String subject, Long expMillis, Map<String, String> claims, String signingKey) {
		  
		logger.debug("generating JWT");
		
	    String uuid = UUID.randomUUID().toString();
	    long nowMillis = System.currentTimeMillis();
	    Date now = new Date(nowMillis);

	    //Let's set the JWT Claims
	    JwtBuilder jwtBuilder = getJwtBuilder(signingKey);
		jwtBuilder.setId(uuid)
			.setIssuedAt(now)
			.setSubject(subject)
			.setIssuer(issuer);
		
		// ELLA claim(JwtConst.AUTHORITIES_KEY, roles) FOREACH
		for (Map.Entry<String, String> entry : claims.entrySet()) {
			jwtBuilder.claim(entry.getKey(), entry.getValue());
		}
		
		// if it has been specified, let's add the expiration
	    if(expMillis != null) {
			expMillis = nowMillis + expMillis;
			Date exp = new Date(expMillis);
			jwtBuilder.setExpiration(exp);
		}
	    
	    //Builds the JWT and serializes it to a compact, URL-safe string
	    return jwtBuilder.compact();
	}
	
	private JwtBuilder getJwtBuilder(String signingKey) {
		//The JWT signature algorithm we will be using to sign the token
	    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; //FIXME 환경으로 빼기
	    
		JwtBuilder jwtBuilder = Jwts.builder()
				.signWith(signatureAlgorithm, signingKey);
		
		return jwtBuilder;
	}
	
}
