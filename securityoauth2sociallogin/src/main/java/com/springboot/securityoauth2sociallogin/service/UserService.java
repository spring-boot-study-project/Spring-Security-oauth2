package com.springboot.securityoauth2sociallogin.service;

import org.springframework.stereotype.Service;

import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.User;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public void register(String registrationId, ProviderUser providerUser) {

        User user = User.builder().registrationId(registrationId)
                .id(providerUser.getId())
                .username(providerUser.getUsername())
                .password(providerUser.getPassword())
                .authorities(providerUser.getAuthorities())
                .provider(providerUser.getProvider())
                .email(providerUser.getEmail())
                .picture(providerUser.getPicture())
                .build();

        userRepository.register(user);
    }
}
