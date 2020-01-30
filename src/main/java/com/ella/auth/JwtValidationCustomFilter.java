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

		String headerAuth = req.getHeader(SHD_TOKEN_KEY);
		String token = null;

		// get token
		if (headerAuth != null && headerAuth.startsWith(TOKEN_PREFIX)) {
			token = headerAuth.replace(TOKEN_PREFIX, "");
		} else if (headerAuth != null && headerAuth.startsWith(BEARER_PREFIX)) {
			token = headerAuth.replace(BEARER_PREFIX, "");
		} else if (headerAuth != null && headerAuth.startsWith(getMyTokenPrefix())) { 
			token = headerAuth.replace(getMyTokenPrefix(), ""); //FIXME  headerAuth.replace 로직 변경 필요
		} else {
			logger.warn("couldn't find token string");
		}

		// validate token
		while (token != null) {
			
			if(jwtValidator.validateToken(token)) {
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

	// ELLA Custom prefix
	protected String getMyTokenPrefix() {
		return "please add myTokenPrefix";
	}

	// ELLA Custom method
	protected void doFilterInternalExtra(DefaultHeader<?> headerClaims, Claims bodyClaims) {
		System.out.println("doFilterInternalExtra");
	}

}
