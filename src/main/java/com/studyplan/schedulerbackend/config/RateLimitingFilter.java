package com.studyplan.schedulerbackend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.studyplan.schedulerbackend.dto.ErrorResponse;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);
    private final boolean enabled;
    private final long loginCapacity;
    private final long loginRefillTokens;
    private final String loginRefillDuration;
    private final long signupCapacity;
    private final long signupRefillTokens;
    private final String signupRefillDuration;
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> signupBuckets = new ConcurrentHashMap<>();

    public RateLimitingFilter(
            @Value("${rate-limiting.enabled:true}") boolean enabled,
            @Value("${rate-limiting.login.capacity:5}") long loginCapacity,
            @Value("${rate-limiting.login.refill-tokens:5}") long loginRefillTokens,
            @Value("${rate-limiting.login.refill-duration:PT1H}") String loginRefillDuration,
            @Value("${rate-limiting.signup.capacity:3}") long signupRefillTokens,
            @Value("${rate-limiting.signup.refill-tokens:3}") long signupCapacity,
            @Value("${rate-limiting.signup.refill-duration:PT1H}") String signupRefillDuration) {
        this.enabled = enabled;
        this.loginCapacity = loginCapacity;
        this.loginRefillTokens = loginRefillTokens;
        this.loginRefillDuration = loginRefillDuration;
        this.signupCapacity = signupCapacity;
        this.signupRefillTokens = signupRefillTokens;
        this.signupRefillDuration = signupRefillDuration;
        logger.info("RateLimitingFilter initialized with enabled={}, loginCapacity={}, loginRefillTokens={}, loginRefillDuration={}, signupCapacity={}, signupRefillTokens={}, signupRefillDuration={}",
                enabled, loginCapacity, loginRefillTokens, loginRefillDuration, signupCapacity, signupRefillTokens, signupRefillDuration);
    }

    private Bucket createBucket(long capacity, long refillTokens, String duration, String bucketType) {
        try {
            Duration parsedDuration = Duration.parse(duration);
            logger.debug("Parsed {} duration: {} to {}", bucketType, duration, parsedDuration);
            return Bucket.builder()
                    .addLimit(Bandwidth.classic(capacity, Refill.intervally(refillTokens, parsedDuration)))
                    .build();
        } catch (Exception e) {
            logger.error("Failed to parse {} duration: {}. Using default 1h.", bucketType, duration, e);
            return Bucket.builder()
                    .addLimit(Bandwidth.classic(capacity, Refill.intervally(refillTokens, Duration.ofHours(1))))
                    .build();
        }
    }

    private Bucket getBucket(String clientIp, String path) {
        if (path.equals("/api/login") || path.equals("/api/forgot-password") || path.equals("/api/reset-password")) {
            return loginBuckets.computeIfAbsent(clientIp, k -> createBucket(loginCapacity, loginRefillTokens, loginRefillDuration, "login"));
        } else if (path.equals("/api/register")) {
            return signupBuckets.computeIfAbsent(clientIp, k -> createBucket(signupCapacity, signupRefillTokens, signupRefillDuration, "signup"));
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!enabled) {
            logger.debug("Rate limiting is disabled. Proceeding with request: {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }
        String path = request.getRequestURI();
        String clientIp = request.getRemoteAddr();
        Bucket bucket = getBucket(clientIp, path);
        if (bucket != null) {
            logger.debug("Checking rate limit for IP: {} on path: {}", clientIp, path);
            if (!bucket.tryConsume(1)) {
                logger.warn("Rate limit exceeded for request: {} from IP: {}", path, clientIp);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(
                        new ObjectMapper().writeValueAsString(
                                new ErrorResponse("Too Many Requests", "Rate limit exceeded")
                        )
                );
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}