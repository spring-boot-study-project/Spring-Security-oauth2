package com.springboot.securityoauth2sociallogin.common.converters;

import com.springboot.securityoauth2sociallogin.model.users.ProviderUser;
import com.springboot.securityoauth2sociallogin.model.users.User;
import com.springboot.securityoauth2sociallogin.model.users.forms.FormUser;

public final class UserDetailsProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    @Override
    public ProviderUser convert(ProviderUserRequest providerUserRequest) {

        if (providerUserRequest.user() == null) {
            return null;
        }

        User user = providerUserRequest.user();
        return FormUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities())
                .email(user.getEmail())
                .provider("none")
                .build();
    }
}
