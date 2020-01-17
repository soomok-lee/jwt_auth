package com.ella.auth;

import java.util.Date;

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
	public String generateJWT(String id, String issuer, String subject, String roles) {
		  
		logger.debug("generating JWT");
		
	    //The JWT signature algorithm we will be using to sign the token
	    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

	    long nowMillis = System.currentTimeMillis();
	    Date now = new Date(nowMillis);

	    String signingKey = jwtConst.getSigningKey(issuer);
	    //Let's set the JWT Claims
	    JwtBuilder builder = Jwts.builder()
	    		.claim(JwtConst.AUTHORITIES_KEY, roles)
	    		.setId(id)
	            .setIssuedAt(now)
	            .setSubject(subject)
	            .setIssuer(issuer)
	            .signWith(signatureAlgorithm, signingKey);
	  
		// if it has been specified, let's add the expiration
		long expMillis = nowMillis + JwtConst.TTL_MILLIS;
		Date exp = new Date(expMillis);
		builder.setExpiration(exp);
	    
	    //Builds the JWT and serializes it to a compact, URL-safe string
	    return builder.compact();
	}
	
}
