package com.springboot.securityoauth2sociallogin.service;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.springboot.securityoauth2sociallogin.certification.SelfCertification;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserConverter;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserRequest;
import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;
import com.springboot.securityoauth2sociallogin.model.users.PrincipalUser;

@Service
public class CustomOidcUserService extends AbstractOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    public CustomOidcUserService(
        UserService userService, UserRepository userRepository,
        SelfCertification certification,
        ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter
    ) {
        super(userService, userRepository, certification, providerUserConverter);
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        // Open ID Connect 인 경우 User name Attribute Key 가 sub 이기 때문에 재정의함
        ClientRegistration clientRegistration = ClientRegistration
                .withClientRegistration(userRequest.getClientRegistration())
                .userNameAttributeName("sub")
                .build();

        OidcUserRequest oidcUserRequest = new OidcUserRequest(
            clientRegistration, userRequest.getAccessToken(), userRequest.getIdToken(), userRequest.getAdditionalParameters()
        );

        OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(oidcUserRequest);

        ProviderUserRequest providerUserRequest = new ProviderUserRequest(clientRegistration, oidcUser);
        ProviderUser providerUser = providerUser(providerUserRequest);

        selfCertificate(providerUser);

        super.register(providerUser, oidcUserRequest);

        return new PrincipalUser(providerUser);
    }
}
