package com.studyplan.schedulerbackend.service;

import com.studyplan.schedulerbackend.entity.OAuth2Token;
import com.studyplan.schedulerbackend.entity.User;
import com.studyplan.schedulerbackend.repository.OAuth2TokenRepository;
import com.studyplan.schedulerbackend.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);
    private final UserRepository userRepository;
    private final OAuth2TokenRepository tokenRepository;

    public CustomOAuth2UserService(UserRepository userRepository, OAuth2TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        logger.debug("CustomOAuth2UserService instantiated");
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        logger.info("Loading OAuth2 user for registrationId={}", userRequest.getClientRegistration().getRegistrationId());
        try {
            OAuth2User oauthUser = super.loadUser(userRequest);

            String provider = userRequest.getClientRegistration().getRegistrationId();
            String providerId = Optional.ofNullable(oauthUser.getAttribute("sub"))
                    .orElseGet(() -> Optional.ofNullable(oauthUser.getAttribute("id"))
                            .orElseThrow(() -> new IllegalStateException("No provider ID found in OAuth2 attributes")))
                    .toString();
            String email = oauthUser.getAttribute("email");
            String accessToken = userRequest.getAccessToken().getTokenValue();
            String refreshToken = Optional.ofNullable(userRequest.getAdditionalParameters().get("refresh_token"))
                    .map(Object::toString)
                    .orElse(null);
            Instant expiresAt = userRequest.getAccessToken().getExpiresAt();

            if (email == null || providerId == null) {
                logger.error("Missing email or providerId in OAuth2 attributes: email={}, providerId={}", email, providerId);
                throw new IllegalStateException("OAuth2 provider did not return required attributes");
            }

            Optional<User> userOpt = userRepository.findByProviderAndProviderId(provider, providerId);
            User user;
            if (userOpt.isPresent()) {
                user = userOpt.get();
                if (!email.equalsIgnoreCase(user.getEmail())) {
                    user.setEmail(email);
                    user = userRepository.save(user);
                    logger.info("Updated existing OAuth2 user email for id={}", user.getId());
                }
            } else {
                User newUser = new User();
                newUser.setEmail(email);
                newUser.setProvider(provider);
                newUser.setProviderId(providerId);
                newUser.setRole("USER");
                user = userRepository.save(newUser);
                logger.info("Saved new OAuth2 user: id={}, email={}, provider={}, providerId={}",
                        user.getId(), user.getEmail(), user.getProvider(), user.getProviderId());
            }

            Optional<OAuth2Token> tokenOpt = tokenRepository.findByUserIdAndProvider(user.getId(), provider);
            OAuth2Token token;
            if (tokenOpt.isPresent()) {
                token = tokenOpt.get();
                token.setAccessToken(accessToken);
                token.setRefreshToken(refreshToken);
                token.setExpiresAt(expiresAt);
            } else {
                token = new OAuth2Token(user, provider, accessToken, refreshToken, expiresAt);
            }
            tokenRepository.save(token);
            logger.info("Saved OAuth2 token for user id={}, provider={}", user.getId(), provider);

            return new DefaultOAuth2User(
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                    oauthUser.getAttributes(),
                    "email"
            );
        } catch (Exception ex) {
            logger.error("Error processing OAuth2 user: {}", ex.getMessage(), ex);
            throw new RuntimeException("Could not process OAuth2 user", ex);
        }
    }
}