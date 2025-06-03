package com.springboot.securityoauth2sociallogin.service;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.stereotype.Service;

import com.springboot.securityoauth2sociallogin.certification.SelfCertification;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserConverter;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserRequest;
import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.User;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Service
@Getter
@RequiredArgsConstructor
public abstract class AbstractOAuth2UserService {

    private final UserService userService;

    protected final UserRepository userRepository;

    private final SelfCertification certification;
    
    private final ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter;

    public void selfCertificate(ProviderUser providerUser) {
        certification.checkCertification(providerUser);
    }

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {

        User user = userRepository.findByUsername(providerUser.getUsername());

        if (user == null) {
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            userService.register(clientRegistration.getRegistrationId(), providerUser);
        } else {
            System.out.println("userRequest = " + userRequest);
        }
    }

    public ProviderUser providerUser(ProviderUserRequest providerUserRequest) {
        return providerUserConverter.convert(providerUserRequest);
    }
}
