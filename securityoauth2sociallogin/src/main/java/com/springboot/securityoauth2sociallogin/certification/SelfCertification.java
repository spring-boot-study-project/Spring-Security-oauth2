package com.springboot.securityoauth2sociallogin.certification;

import org.springframework.stereotype.Component;

import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.User;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SelfCertification {

    private final UserRepository userRepository;

    public void checkCertification(ProviderUser providerUser) {
        User user = userRepository.findByUsername(providerUser.getId());
        // if(user != null) {
        boolean bool = providerUser.getProvider().equals("none") || providerUser.getProvider().equals("naver");
        providerUser.isCertificated(bool);
        // }
    }

    public void certificate(ProviderUser providerUser) {

    }
}
