package com.ella.auth;

import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.DefaultJwtParser;

public class JwtProviderImpl implements JwtProvider {

	private final Logger logger = LoggerFactory.getLogger(this.getClass()); // log 생성한 class 지정

	private JwtConst jwtConst;
	
	public JwtProviderImpl(JwtConst jwtConst) {
		super();
		this.jwtConst = jwtConst;
	}
	
	@Override
	public String getNameFromToken(String token) {
		Claims claims = getAllClaimsFromToken(token);
		
		return claims.get("name").toString();
	}
	
	@Override
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }
    
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    
	private Claims getAllClaimsFromToken(String token) { // without signingKey
		String[] splitToken = token.split("\\.");
		String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";

		DefaultJwtParser parser = new DefaultJwtParser();
	        Jwt<?, ?> jwt = parser.parse(unsignedToken);
	        Claims claims = (Claims) jwt.getBody();
		return claims;
	}
	
	private Boolean isTokenExpired(Date iat) {
		return !new Date().before(DateUtils.addSeconds(iat, 3600)); // iat+1hr 
	}

	@Override
	public Claims getClaimsFromToken(String token) {
		
		String signingKey = jwtConst.getSigningKey();

		try {
			byte[] decodedKey = Base64.getDecoder().decode(signingKey);
			Jwts.parser().setSigningKey(decodedKey).parseClaimsJws(token).getBody(); // Signing key validation
		} catch (SignatureException ex) {
			logger.error("Invalid JWT signature");
		} catch (MalformedJwtException ex) {
			logger.error("Invalid JWT token");
		} catch (ExpiredJwtException ex) {
			logger.error("Expired JWT token");
		} catch (UnsupportedJwtException ex) {
			logger.error("Unsupported JWT token");
		} catch (IllegalArgumentException ex) {
			logger.error("JWT claims string is empty.");
		}
		
		final Claims claims = getAllClaimsFromToken(token);
		Date iat = claims.getIssuedAt();
		
//		if(iat == null || isTokenExpired(iat)) {
//			return null;
//		}
		
		return claims;
	}

}
