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
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwtParser;

public class JwtValidatorImpl implements JwtValidator {

	private final Logger logger = LoggerFactory.getLogger(this.getClass()); // log 생성한 class 지정

	private JwtConst jwtConst;

	public JwtValidatorImpl(JwtConst jwtConst) {
		super();
		this.jwtConst = jwtConst;
	}

	private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getBodyClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Boolean isTokenExpired(Date exp) {
		return !new Date().before(exp);
	}

	private String getSigningKeyByIssuer(String issuer) {
		return jwtConst.getSigningKey(issuer);
	}

	private Jwt<?, ?> getJwtFromToken(String token) {
		String[] splitToken = token.split("\\.");
		String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";

		DefaultJwtParser parser = new DefaultJwtParser();
		Jwt<?, ?> jwt = parser.parse(unsignedToken);

		return jwt;
	}

	@Override
	public DefaultHeader<?> getHeaderClaimsFromToken(String token) { // without signingKey
		Jwt<?, ?> jwt = getJwtFromToken(token);
		DefaultHeader<?> headerClaims =  (DefaultHeader<?>) jwt.getHeader();
		
		return headerClaims;
	}

	@Override
	public Claims getBodyClaimsFromToken(String token) { // without signingKey
		Jwt<?, ?> jwt = getJwtFromToken(token);
		Claims bodyClaims = (Claims) jwt.getBody();
			
		return bodyClaims;
	};
	
	@Override
	public JwtClaims getAllClaimsFromToken(String token) {
		Jwt<?, ?> jwt = getJwtFromToken(token);
		JwtClaims jwtClaims = new JwtClaims();
		
		jwtClaims.setHeaderClaims((DefaultHeader<?>) jwt.getHeader());
		jwtClaims.setBodyClaims((Claims) jwt.getBody());
		
		return jwtClaims;
	}

	@Override
	public Boolean validateToken(String token) {

		String signingKey = getSigningKeyByIssuer(getClaimFromToken(token, Claims::getIssuer));

		try {
			byte[] decodedKey = Base64.getDecoder().decode(signingKey);
			Jwts.parser().setSigningKey(decodedKey).parseClaimsJws(token).getBody(); // Signing key validation

			final Claims claims = getBodyClaimsFromToken(token);
			Date exp = claims.getExpiration();
			Date iat = claims.getIssuedAt();

			// when exp exist then exp check, when no exp ant iat exist then iat + ttl check
			boolean a = isTokenExpired(exp);
			if(exp != null) {
				if(isTokenExpired(exp)) {
					throw new ExpiredJwtException(null, claims, "exp expired : " + exp);
				} 
					return true;
			} else if (iat != null) {
				if(isTokenExpired(DateUtils.addSeconds(iat, jwtConst.getIatTTLSeconds()))) {
					throw new ExpiredJwtException(null, claims, "iat expired : " + iat);
				} 
				return true;
			} else {
				throw new ExpiredJwtException(null, claims, "exp/iat not exists");
			}
			
		} catch (SignatureException ex) {
			logger.error("Invalid JWT signature", ex);
		} catch (MalformedJwtException ex) {
			logger.error("Invalid JWT token", ex);
		} catch (ExpiredJwtException ex) {
			logger.error("Expired JWT token", ex);
		} catch (UnsupportedJwtException ex) {
			logger.error("Unsupported JWT token", ex);
		} catch (IllegalArgumentException ex) {
			logger.error("JWT claims string is empty.", ex);
		}

		return false;
	}

	

}
