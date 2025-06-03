package com.springboot.securityoauth2sociallogin.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.springboot.securityoauth2sociallogin.certification.SelfCertification;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserConverter;
import com.springboot.securityoauth2sociallogin.common.converters.ProviderUserRequest;
import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.User;
import com.springboot.securityoauth2sociallogin.repository.UserRepository;

import com.springboot.securityoauth2sociallogin.model.users.PrincipalUser;

@Service
public class CustomUserDetailsService extends AbstractOAuth2UserService implements UserDetailsService {

    public CustomUserDetailsService(
        UserService userService, UserRepository userRepository,
        SelfCertification certification,
        ProviderUserConverter<ProviderUserRequest, ProviderUser> providerUserConverter
    ) {
        super(userService, userRepository, certification, providerUserConverter);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username);

        if (user == null) {
            user = User.builder()
                    .id("1")
                    .username("onjsdnjs")
                    .password("{noop}1234")
                    .authorities(AuthorityUtils.createAuthorityList("ROLE_USER"))
                    .email("onjsdnjs@gmail.com")
                    .build();
        }

        ProviderUserRequest providerUserRequest = new ProviderUserRequest(user);
        ProviderUser providerUser = providerUser(providerUserRequest);

        selfCertificate(providerUser);

        return new PrincipalUser(providerUser);
    }
}
