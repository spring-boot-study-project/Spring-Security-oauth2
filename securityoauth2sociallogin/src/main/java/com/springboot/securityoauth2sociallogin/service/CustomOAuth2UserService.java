package com.springboot.securityoauth2sociallogin.service;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.springboot.securityoauth2sociallogin.certification.SelfCertification;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserConverter;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserRequest;
import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;
import com.springboot.securityoauth2sociallogin.model.users.PrincipalUser;

@Service
public class CustomOAuth2UserService extends AbstractOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    public CustomOAuth2UserService(
        UserService userService, UserRepository userRepository,
        SelfCertification certification,
        ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter
    ) {
        super(userService, userRepository, certification, providerUserConverter);
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

        ProviderUserRequest providerUserRequest = new ProviderUserRequest(clientRegistration, oAuth2User);
        ProviderUser providerUser = providerUser(providerUserRequest);

        // 본인인증 체크
        // 기본은 본인인증을 하지 않은 상태임
        selfCertificate(providerUser);

        super.register(providerUser, userRequest);

        return new PrincipalUser(providerUser);
    }
}
