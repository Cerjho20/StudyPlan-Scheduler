package com.studyplan.schedulerbackend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.studyplan.schedulerbackend.dto.ErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtDecoder jwtDecoder;

    public JwtAuthenticationFilter(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                Jwt jwt = jwtDecoder.decode(token);
                logger.info("JWT claims: subject={}, roles={}", jwt.getSubject(), jwt.getClaim("roles"));
                String username = jwt.getSubject();
                Object rolesClaim = jwt.getClaim("roles");
                List<String> roles = new ArrayList<>();
                if (rolesClaim instanceof List) {
                    roles = ((List<?>) rolesClaim).stream()
                            .filter(String.class::isInstance)
                            .map(Object::toString)
                            .collect(Collectors.toList());
                }
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                logger.info("JWT validated for user: {}, authorities: {}", username, authorities);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                logger.error("JWT validation failed: token={}, error={}", token, e.getMessage(), e);
                SecurityContextHolder.clearContext();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(
                        new ObjectMapper().writeValueAsString(
                                new ErrorResponse("Unauthorized", "Invalid JWT: " + e.getMessage())
                        )
                );
                return;
            }
        } else {
            logger.debug("No JWT found in request: {}", request.getRequestURI());
        }
        filterChain.doFilter(request, response);
    }
}