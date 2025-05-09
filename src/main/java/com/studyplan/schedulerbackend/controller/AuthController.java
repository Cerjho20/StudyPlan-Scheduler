package com.studyplan.schedulerbackend.controller;

import com.studyplan.schedulerbackend.dto.*;
import com.studyplan.schedulerbackend.entity.User;
import com.studyplan.schedulerbackend.repository.UserRepository;
import com.studyplan.schedulerbackend.service.PasswordResetService;
import com.studyplan.schedulerbackend.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetService passwordResetService;

    public AuthController(
            AuthenticationManager authenticationManager,
            TokenService tokenService,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            PasswordResetService passwordResetService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            logger.info("Attempting login for email={}", maskEmail(loginRequest.getEmail()));
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );
            String token = tokenService.generateToken(authentication);
            logger.info("Login successful for email={}", maskEmail(loginRequest.getEmail()));
            return ResponseEntity.ok(new LoginResponse(token));
        } catch (AuthenticationException e) {
            logger.error("Login failed for email={}: {}", maskEmail(loginRequest.getEmail()), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized", "Invalid email or password"));
        }
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        logger.info("Processing logout request");
        new SecurityContextLogoutHandler().logout(request, response, null);
        logger.info("User logged out successfully");
        return "Logged out successfully";
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        logger.debug("Attempting registration for email={}", registerRequest.getEmail());
        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()) {
            logger.warn("Registration failed: Email {} already exists", registerRequest.getEmail());
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Bad Request", "Email already exists"));
        }
        try {
            User user = new User();
            user.setEmail(registerRequest.getEmail());
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setRole("USER");
            userRepository.save(user);

            logger.info("User registered successfully: email={}", registerRequest.getEmail());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    registerRequest.getEmail(), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
            String token = tokenService.generateToken(authentication);
            return ResponseEntity.ok(new RegisterResponse(token));
        } catch (Exception e) {
            logger.error("Registration failed for email={}: {}", registerRequest.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal Server Error", "Registration failed"));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest httpRequest) {
        try {
            if (userRepository.findByEmail(request.getEmail()).isPresent()) {
                passwordResetService.initiatePasswordReset(request.getEmail(), httpRequest);
            }
            return ResponseEntity.ok("If an account exists for this email, a password reset link has been sent.");
        } catch (jakarta.mail.MessagingException e) {
            logger.error("Forgot password failed due to mail error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal Server Error", "Failed to send password reset email"));
        } catch (Exception e) {
            logger.error("Forgot password failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal Server Error", "Failed to process password reset request"));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
            return ResponseEntity.ok("Password reset successful");
        } catch (IllegalArgumentException e) {
            logger.warn("Reset password failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Bad Request", e.getMessage()));
        } catch (Exception e) {
            logger.error("Reset password failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Internal Server Error", "Failed to reset password"));
        }
    }

    @GetMapping("/protected")
    public ResponseEntity<String> protectedResource() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Accessing protected resource for user: {}", username);
        return ResponseEntity.ok("This is a protected resource");
    }

    private String maskEmail(String email) {
        if (email == null) return "null";
        int atIndex = email.indexOf('@');
        if (atIndex <= 2) return email;
        return email.substring(0, 2) + "****" + email.substring(atIndex);
    }
}
