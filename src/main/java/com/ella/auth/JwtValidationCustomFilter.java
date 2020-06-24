package com.ella.auth;

import static com.ella.auth.JwtConst.BEARER_PREFIX;
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

public class JwtValidationCustomFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private JwtValidator jwtValidator;

	public JwtValidationCustomFilter(JwtValidator jwtValidator) {
		super();
		this.jwtValidator = jwtValidator;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws ServletException, IOException {

		String headerAuth = null;
		String token = null;
		
		headerAuth = req.getHeader(getMyHeaderAuthName());
		
		if (headerAuth != null) {
			String[] headerAuthParts = headerAuth.split(" ");
			if (headerAuthParts.length == 1) {
				token = headerAuthParts[0];
			} else if (headerAuthParts.length == 2 && (headerAuth.startsWith(TOKEN_PREFIX) || headerAuth.startsWith(BEARER_PREFIX) || headerAuth.startsWith(getMyTokenPrefix()))) {
				token = headerAuthParts[1];
			} else {
				logger.warn("headerAuth structure is not right");
			}
		} else {
			logger.warn("couldn't find headerAuth");
		}

		// validate token
		while (token != null) {

			if (jwtValidator.validateToken(token)) {
				logger.info("token validation completed");

				DefaultHeader<?> headerClaims = jwtValidator.getHeaderClaimsFromToken(token);
				Claims bodyClaims = jwtValidator.getBodyClaimsFromToken(token);

				doFilterInternalExtra(headerClaims, bodyClaims);
			} else {
				logger.info("token validation failed");
			}

			break;
		}

		chain.doFilter(req, res);
	}

	// ELLA Custom headerAuthName
	protected String getMyHeaderAuthName() {
		return "myHeaderAuthName";
	}
		
	// ELLA Custom prefix
	protected String getMyTokenPrefix() {
		return "myTokenPrefix";
	}

	// ELLA Custom method
	protected void doFilterInternalExtra(DefaultHeader<?> headerClaims, Claims bodyClaims) {
		System.out.println("doFilterInternalExtra");
	}

}
