package com.springboot.securityoauth2sociallogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import com.springboot.securityoauth2sociallogin.common.authority.CustomAuthorityMapper;

@Configuration
public class OAuth2AppConfig {

    @Bean
    public GrantedAuthoritiesMapper customAuthorityMapper() {
        return new CustomAuthorityMapper();
    }

}
