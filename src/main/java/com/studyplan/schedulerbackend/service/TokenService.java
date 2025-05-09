// src/main/java/com/studyplan/schedulerbackend/service/TokenService.java
package com.studyplan.schedulerbackend.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class TokenService {
    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);
    private final JwtEncoder jwtEncoder;
    private final long expiration;

    /**
     * Constructor for TokenService.
     *
     * @param jwtEncoder  the JwtEncoder used to create JWT tokens
     * @param expiration  the expiration time for the tokens in milliseconds
     */
    public TokenService(JwtEncoder jwtEncoder, @Value("${jwt.expiration}") long expiration) {
        this.jwtEncoder = jwtEncoder;
        this.expiration = expiration;
    }

    /**
     * Generates a JWT token for the given authentication.
     *
     * @param authentication the authentication object containing user details
     * @return a JWT token as a string
     */
    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        logger.info("Generating token for user: {}, roles: {}", authentication.getName(), roles);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusMillis(expiration))
                .subject(authentication.getName())
                .claim("roles", roles)
                .build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        logger.info("Generated token: {}", token);
        return token;
    }
}