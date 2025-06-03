package com.springboot.securityoauth2sociallogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.springboot.securityoauth2sociallogin.service.CustomOAuth2UserService;
import com.springboot.securityoauth2sociallogin.service.CustomOidcUserService;
import com.springboot.securityoauth2sociallogin.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/static/js/**", "/static/images/**", "/static/css/**",
                "/static/scss/**");
    }

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                // .antMatchers("/loginProc").permitAll()
                .requestMatchers("/api/user")
                .hasAnyRole("SCOPE_profile", "SCOPE_profile_image", "SCOPE_email")
                // .access("hasAuthority('SCOPE_profile')")
                .requestMatchers("/api/oidc")
                .hasRole("SCOPE_openid")
                // .access("hasAuthority('SCOPE_openid')")
                .requestMatchers("/")
                .permitAll()
                .anyRequest().authenticated());
        http.formLogin(login -> login.loginPage("/login")
            .loginProcessingUrl("/loginProc")
            .defaultSuccessUrl("/")
            .permitAll()
        );
        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(customOAuth2UserService) // OAuth2
                        .oidcUserService(customOidcUserService))); // OpenID Connect
        http.userDetailsService(customUserDetailsService); // Form
        http.exceptionHandling(
                exceptionHandlingConfigurer -> exceptionHandlingConfigurer.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        http.logout(logout -> logout.logoutSuccessUrl("/"));
        return http.build();
    }
}
