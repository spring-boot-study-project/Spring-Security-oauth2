package com.springboot.securityoauth2sociallogin.model.users.social;

import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.springboot.securityoauth2sociallogin.model.Attributes;

public class KakaoUser extends OAuth2ProviderUser {

    private final Map<String, Object> subAttributes;

    public KakaoUser(Attributes attributes, OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(attributes.getSubAttributes(), oAuth2User, clientRegistration);
        this.subAttributes = attributes.getOtherAttributes();

    }

    @Override
    public String getId() {
        return (String) getAttributes().get("id");
    }

    @Override
    public String getUsername() {
        return (String) subAttributes.get("nickname");
    }

    @Override
    public String getPicture() {
        return (String) subAttributes.get("profile_image_url");
    }
}
