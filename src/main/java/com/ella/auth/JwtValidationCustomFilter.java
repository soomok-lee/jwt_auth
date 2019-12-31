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

public class JwtValidationCustomFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private JwtProvider jwtProvider;

	public JwtValidationCustomFilter(JwtProvider jwtProvider) {
		super();
		this.jwtProvider = jwtProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws ServletException, IOException {

		String header = req.getHeader(SHD_TOKEN_KEY);
		String token = null;

		// get token
		if (header != null && header.startsWith(TOKEN_PREFIX)) {
			token = header.replace(TOKEN_PREFIX, "");
		} else if (header != null && header.startsWith(BEARER_PREFIX)) {
			token = header.replace(BEARER_PREFIX, "");
		} else {
			logger.warn("couldn't find token string");
		}

		// validate token
		while (token != null) {
			Claims claims = jwtProvider.getClaimsFromToken(token);
			
			if (claims != null) {
				logger.info("token validation completed");
				
				customMethod(claims);
			} else {
				logger.info("token validation failed");
			}

			break;
		}
		
		chain.doFilter(req, res);
	}

	// ELLA Custom method
	protected void customMethod(Claims claims) {
		System.out.println("customMethod");
	}

}
