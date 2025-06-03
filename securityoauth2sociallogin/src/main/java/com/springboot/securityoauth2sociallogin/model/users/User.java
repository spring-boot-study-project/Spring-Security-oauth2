package com.springboot.securityoauth2sociallogin.model.users;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class User {

    private String registrationId;
    private String id;
    private String ci;
    private String username;
    private String password;
    private String provider;
    private String email;
    private String picture;
    private List<? extends GrantedAuthority> authorities;

}
