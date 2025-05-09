package com.studyplan.schedulerbackend.service;

import com.studyplan.schedulerbackend.entity.OAuth2Token;
import com.studyplan.schedulerbackend.entity.User;
import com.studyplan.schedulerbackend.entity.UserIdentity;
import com.studyplan.schedulerbackend.repository.OAuth2TokenRepository;
import com.studyplan.schedulerbackend.repository.UserIdentityRepository;
import com.studyplan.schedulerbackend.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

@Component
public class OAuth2UserProcessor {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2UserProcessor.class);

    private final UserRepository userRepository;
    private final OAuth2TokenRepository tokenRepository;
    private final UserIdentityRepository identityRepository;

    public OAuth2UserProcessor(UserRepository userRepository,
                               OAuth2TokenRepository tokenRepository,
                               UserIdentityRepository identityRepository) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.identityRepository = identityRepository;
    }

    public OAuth2User process(OAuth2UserRequest userRequest, OAuth2User oauthUser) {
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = Optional.ofNullable(oauthUser.getAttribute("sub"))
                .orElseGet(() -> Optional.ofNullable(oauthUser.getAttribute("id"))
                        .orElseThrow(() -> new IllegalStateException("No provider ID found")))
                .toString();
        String email = oauthUser.getAttribute("email");
        String accessToken = userRequest.getAccessToken().getTokenValue();
        String refreshToken = Optional.ofNullable(userRequest.getAdditionalParameters().get("refresh_token"))
                .map(Object::toString).orElse(null);
        Instant expiresAt = userRequest.getAccessToken().getExpiresAt();

        logger.debug("OAuth2 attributes: email={}, providerId={}, provider={}", email, providerId, provider);

        if (email == null || providerId == null) {
            throw new IllegalStateException("OAuth2 provider did not return required attributes");
        }

        User user = identityRepository.findByProviderAndProviderId(provider, providerId)
                .map(UserIdentity::getUser)
                .orElseGet(() -> {
                    User u = userRepository.findByEmail(email).orElseGet(() -> {
                        User newUser = new User();
                        newUser.setEmail(email);
                        newUser.setRole("USER");
                        return userRepository.save(newUser);
                    });
                    UserIdentity identity = new UserIdentity();
                    identity.setUser(u);
                    identity.setProvider(provider);
                    identity.setProviderId(providerId);
                    identityRepository.save(identity);
                    logger.info("Created new user identity for userId={}, provider={}, providerId={}", u.getId(), provider, providerId);
                    return u;
                });

        OAuth2Token token = tokenRepository.findByUserIdAndProvider(user.getId(), provider)
                .orElse(new OAuth2Token(user, provider, accessToken, refreshToken, expiresAt));
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setExpiresAt(expiresAt);
        tokenRepository.save(token);

        logger.info("Persisted OAuth2 token for userId={}, provider={}", user.getId(), provider);

        return new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                oauthUser.getAttributes(),
                "email"
        );
    }
}
