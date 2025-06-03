package com.springboot.securityoauth2sociallogin.common.converters;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.springboot.securityoauth2sociallogin.model.users.User;

public record ProviderUserRequest(ClientRegistration clientRegistration, OAuth2User oAuth2User, User user) {
    public ProviderUserRequest(ClientRegistration clientRegistration, OAuth2User oAuth2User) {
        this(clientRegistration, oAuth2User, null);
    };

    public ProviderUserRequest(User user) {
        this(null, null, user);
    };
}
