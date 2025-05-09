package com.studyplan.schedulerbackend.service;

import com.studyplan.schedulerbackend.entity.PasswordResetToken;
import com.studyplan.schedulerbackend.entity.User;
import com.studyplan.schedulerbackend.repository.PasswordResetTokenRepository;
import com.studyplan.schedulerbackend.repository.UserRepository;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class PasswordResetService {
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final JavaMailSender mailSender;
    private final PasswordEncoder passwordEncoder;
    private final String frontendUrl;
    private final long tokenExpirationMillis;

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            JavaMailSender mailSender,
            PasswordEncoder passwordEncoder,
            @Value("${app.frontend-url}") String frontendUrl,
            @Value("${password-reset.token-expiration:3600000}") long tokenExpirationMillis) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailSender = mailSender;
        this.passwordEncoder = passwordEncoder;
        this.frontendUrl = frontendUrl;
        this.tokenExpirationMillis = tokenExpirationMillis;
    }

    @Transactional
    public void initiatePasswordReset(String email, HttpServletRequest request) throws MessagingException {
        logger.debug("Initiating password reset for email={} from IP={}", email, request.getRemoteAddr());
        // Lookup user by email only (local users assumed)
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));

        tokenRepository.deleteByUserId(user.getId());

        String token = Base64.getUrlEncoder().encodeToString(new SecureRandom().generateSeed(32));
        String tokenHash = DigestUtils.sha256Hex(token);
        Instant expiryDate = Instant.now().plusMillis(tokenExpirationMillis);
        PasswordResetToken resetToken = new PasswordResetToken(tokenHash, user, expiryDate);
        tokenRepository.save(resetToken);

        String resetUrl = frontendUrl + "/reset-password?token=" + token;
        sendResetEmail(email, resetUrl);
        logger.info("Password reset email sent to email={} from IP={}", email, request.getRemoteAddr());
    }

    private void sendResetEmail(String email, String resetUrl) throws MessagingException {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(email);
            helper.setSubject("Password Reset Request");
            helper.setText(
                    "<h1>Password Reset</h1>" +
                            "<p>Click the link below to reset your password:</p>" +
                            "<p><a href=\"" + resetUrl + "\">Reset Password</a></p>" +
                            "<p>This link will expire in 1 hour.</p>",
                    true);
            mailSender.send(message);
            logger.info("Password reset email sent to email={}", email);
        } catch (MessagingException e) {
            logger.error("Failed to send password reset email to {}: {}", email, e.getMessage(), e);
            throw e;
        }
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        logger.debug("Attempting password reset with token");
        String tokenHash = DigestUtils.sha256Hex(token);
        PasswordResetToken resetToken = tokenRepository.findByToken(tokenHash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid password reset token"));

        if (resetToken.isExpired()) {
            tokenRepository.delete(resetToken);
            throw new IllegalArgumentException("Password reset token has expired");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        tokenRepository.deleteByUserId(user.getId());
        logger.info("Password reset successful for user email={}", user.getEmail());
    }
}
