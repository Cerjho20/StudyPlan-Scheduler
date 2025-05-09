package com.studyplan.schedulerbackend.service;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomOidcUserService extends OidcUserService {

    private final OAuth2UserProcessor processor;

    public CustomOidcUserService(OAuth2UserProcessor processor) {
        this.processor = processor;
    }

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) {
        // 1) let Spring fetch & build the OidcUser
        OidcUser oidcUser = super.loadUser(userRequest);

        // 2) persist tokens & identities, ignore return value
        processor.process(userRequest, oidcUser);

        // 3) hand back the real OidcUser
        return oidcUser;
    }
}

