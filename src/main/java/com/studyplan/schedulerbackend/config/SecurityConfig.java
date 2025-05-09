package com.studyplan.schedulerbackend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.studyplan.schedulerbackend.repository.UserRepository;
import com.studyplan.schedulerbackend.service.CustomOAuth2UserService;
import com.studyplan.schedulerbackend.service.TokenService;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final JwtDecoder jwtDecoder;
    private final UserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final RateLimitingFilter rateLimitingFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final String[] frontendUrls;

    public SecurityConfig(
            TokenService tokenService,
            UserRepository userRepository,
            JwtDecoder jwtDecoder,
            UserDetailsService userDetailsService,
            CustomOAuth2UserService customOAuth2UserService,
            RateLimitingFilter rateLimitingFilter,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            @Value("${app.frontend-url}") String frontendUrls) {
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
        this.customOAuth2UserService = customOAuth2UserService;
        this.rateLimitingFilter = rateLimitingFilter;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;

        this.frontendUrls = Arrays.stream(frontendUrls.split(","))
                .map(String::trim)
                .filter(url -> !url.isEmpty() && url.matches("^https?://[\\w.-]+(:\\d+)?(/.*)?$"))
                .toArray(String[]::new);
        if (this.frontendUrls.length == 0) {
            logger.error("No valid frontend URLs provided in app.frontend-url");
            throw new IllegalStateException("At least one valid frontend URL is required");
        }
        logger.info("CORS allowed origins: {}", Arrays.toString(this.frontendUrls));
        logger.debug("SecurityConfig initialized with CustomOAuth2UserService: {}", customOAuth2UserService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/login",
                                "/api/register",
                                "/api/forgot-password",
                                "/api/reset-password",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/error"
                        ).permitAll()
                        .requestMatchers(
                                "/default-ui.css"
                        ).denyAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> {
                            logger.debug("Configuring OAuth2 userInfoEndpoint with CustomOAuth2UserService");
                            userInfo.userService(customOAuth2UserService);
                        })
                        .successHandler(oAuth2SuccessHandler())
                        .failureHandler((request, response, exception) -> {
                            logger.error("OAuth2 login failed: {}", exception.getMessage());
                            response.sendRedirect(frontendUrls[0] + "/login?error=oauth2_failure");
                        })
                )
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            logger.warn("Authentication failed for request {}: {}", request.getRequestURI(), authException.getMessage());
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");
                            response.getWriter().write(
                                    "{\"error\": \"Unauthorized\", \"message\": \"" + authException.getMessage() + "\"}"
                            );
                        })
                );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler oAuth2SuccessHandler() {
        return (request, response, authentication) -> {
            try {
                if (!(authentication.getPrincipal() instanceof org.springframework.security.oauth2.core.user.OAuth2User)) {
                    logger.error("Unexpected principal type: {}", authentication.getPrincipal().getClass().getName());
                    response.sendRedirect(frontendUrls[0] + "/login?error=invalid_principal");
                    return;
                }
                org.springframework.security.oauth2.core.user.OAuth2User oAuth2User =
                        (org.springframework.security.oauth2.core.user.OAuth2User) authentication.getPrincipal();
                String email = oAuth2User.getAttribute("email");
                if (email == null) {
                    logger.error("Email not found in OAuth2 user attributes");
                    response.sendRedirect(frontendUrls[0] + "/login?error=missing_email");
                    return;
                }
                logger.info("Generating JWT for OAuth2 user: email={}", email);
                var auth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        email, null, authentication.getAuthorities());
                String token = tokenService.generateToken(auth);
                logger.info("Redirecting to frontend callback with token for email={}", email);
                String redirectUrl = frontendUrls[0] + "/callback?token=" + token;
                response.sendRedirect(redirectUrl);
            } catch (Exception e) {
                logger.error("OAuth2 success handler failed: {}", e.getMessage(), e);
                response.sendRedirect(frontendUrls[0] + "/login?error=oauth2_failure");
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(frontendUrls));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}