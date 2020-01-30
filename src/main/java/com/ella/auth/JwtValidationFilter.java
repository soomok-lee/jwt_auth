package com.ella.auth;

import static com.ella.auth.JwtConst.BEARER_PREFIX;
import static com.ella.auth.JwtConst.SHD_TOKEN_KEY;
import static com.ella.auth.JwtConst.TOKEN_PREFIX;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultHeader;

public class JwtValidationFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private JwtClaims jwtClaims;
	private JwtValidator jwtValidator;

	public JwtValidationFilter(JwtClaims jwtClaims, JwtValidator jwtValidator) {
		super();
		this.jwtClaims = jwtClaims;
		this.jwtValidator = jwtValidator;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws ServletException, IOException {

		String headerAuth = req.getHeader(SHD_TOKEN_KEY);
		String token = null;

		if (headerAuth.startsWith(TOKEN_PREFIX)) {
			token = headerAuth.replace(TOKEN_PREFIX, "");
		} else if (headerAuth.startsWith(BEARER_PREFIX)) {
			token = headerAuth.replace(BEARER_PREFIX, "");
		} else {
			logger.warn("couldn't find token string");
		}

		if (token != null) {
			
			if(jwtValidator.validateToken(token)) {
				logger.info("token validation completed");

				DefaultHeader<?> headerClaims = jwtValidator.getHeaderClaimsFromToken(token);
				Claims bodyClaims = jwtValidator.getBodyClaimsFromToken(token);
				
				try {
					this.jwtClaims.setHeaderClaims(headerClaims);
					this.jwtClaims.setBodyClaims(bodyClaims);
					
					chain.doFilter(req, res);
				} finally {
					this.jwtClaims.getHeaderClaims().clear();
					this.jwtClaims.getBodyClaims().clear();
				}

			} else {
				logger.info("token validation failed");
			}

		}

		chain.doFilter(req, res);
	}
	
}
