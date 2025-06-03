package com.springboot.securityoauth2sociallogin.common.converters;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import com.springboot.securityoauth2sociallogin.common.enums.OAuth2Config;
import com.springboot.securityoauth2sociallogin.common.util.OAuth2Utils;
import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.social.KakaoOidcUser;

public final class OAuth2KakaoOidcProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    
    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {

        if (!providerUserRequest.clientRegistration().getRegistrationId().equals(OAuth2Config.SocialType.KAKAO.getSocialName())) {
            return null;
        }

        if (!(providerUserRequest.oAuth2User() instanceof OidcUser)) {
            return null;
        }

        return new KakaoOidcUser(OAuth2Utils.getMainAttributes(
                providerUserRequest.oAuth2User()),
                providerUserRequest.oAuth2User(),
                providerUserRequest.clientRegistration());
    }
}
