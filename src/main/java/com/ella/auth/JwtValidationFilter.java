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

public class JwtValidationFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private JwtClaims jwtClaims;
	private JwtProvider jwtProvider;

	public JwtValidationFilter(JwtClaims jwtClaims, JwtProvider jwtProvider) {
		super();
		this.jwtClaims = jwtClaims;
		this.jwtProvider = jwtProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws ServletException, IOException {

		String header = req.getHeader(SHD_TOKEN_KEY);
		String token = null;

		if (header.startsWith(TOKEN_PREFIX)) {
			token = header.replace(TOKEN_PREFIX, "");
		} else if (header.startsWith(BEARER_PREFIX)) {
			token = header.replace(BEARER_PREFIX, "");
		} else {
			logger.warn("couldn't find token string");
		}

		if (token != null) {
			Claims claims = jwtProvider.getClaimsFromValidatedToken(token);

			if (claims != null) {
				logger.info("token validation completed");

				try {
					this.jwtClaims.setClaims(claims);
					chain.doFilter(req, res);
				} finally {
					this.jwtClaims.getClaims().clear();
				}

			} else {
				logger.info("token validation failed");

			}

		}

		chain.doFilter(req, res);
	}
	
}
