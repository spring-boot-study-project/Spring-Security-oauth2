package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2LoginAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.resolver.CustomOAuth2AuthorizationRequestResolver;
import lombok.RequiredArgsConstructor;

import static org.springframework.security.config.Customizer.withDefaults;

// import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
// import org.springframework.security.oauth2.client.registration.ClientRegistrations;

// oauth2 자동 설정에 대한 클래스들
// import OAuth2ImportSelector;
// import OAuth2WebSecurityConfiguration;
// import OAuth2ClientConfiguration;
// import OAuth2ClientAutoConfiguration

// oauth2login의 자동 설정에 대한 이해
// import SecurityConfigurer
// import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
// OAuth2LoginAuthenticationFIlter
// OAuth2LoginAuthenticationProvider
// OidcAuthorizationCodeAuthenticationProvider 
// DefaultLoginPageGeneratingFilter
// OAuth2AuthorizationRequestRedirectFilter 

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final ClientRegistrationRepository clientRegistrationRepository;

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    @Bean
    SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(request -> request
                .requestMatchers("/", "/client", "/oauth2Login").permitAll()
                .anyRequest().authenticated())
            // .exceptionHandling(exceptionHandlingConfigurer -> exceptionHandlingConfigurer
            //     .authenticationEntryPoint(new CustomAuthenticationEntryPoint()))
            // .oauth2Login(oauth2Login -> oauth2Login
                // .loginPage("/login")
                // .loginProcessingUrl("/login/v1/oauth2/code/*") // redirectionUrl이 우선순위가 더 높다 하지만 이렇게도 변경 가능
                // .authorizationEndpoint(authorizationEndpointConfig -> 
                //     authorizationEndpointConfig.baseUri("/oauth2/v1/authorization")) // 클라이언트와 맞춰야 됨
                    // .authorizationEndpoint(authEndpoint -> authEndpoint
                    //     .authorizationRequestResolver(customAuthorizationRequestResolver())
                    // )
                // .redirectionEndpoint(redirectionEndpointConfig -> 
                //     redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*")) // yml, 인가 서버 둘다 수정 필요
            // )
            .oauth2Login(authLogin ->
                authLogin.authorizationEndpoint(authEndpoint ->
                    authEndpoint.authorizationRequestResolver(customOAuth2AuthenticationRequestResolver())
                )
            ) // 반면 이 api는 인증까지 처리 해줌
            .oauth2Client(withDefaults()) // 클라이언트에 대한 인가 처리만 해준다. -> 인증까지는 안해줌(1, 2단계 까지만 진행 3단계 진행은 직접 구현)
            // .logout(logout -> logout
            //     .logoutSuccessHandler(oidcLogoutSuccessHandler()) // 로그 아웃을 했을 경우 redirection 설정
            //     .invalidateHttpSession(true) // 로그아웃 시 현재 사용자의 HTTP 세션을 무효화하는 설정
            //     .clearAuthentication(true) // 로그아웃 시 현재 사용자의 인증 정보를 제거하는 설정
            //     .deleteCookies("JSESSIONID")); // 로그아웃 시 현재 사용자의 JSESSIONID 쿠키를 삭제하는 설정
            .addFilterBefore(customOAuth2LoginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .logout(logout -> logout.logoutSuccessUrl("/home"));

        return http.build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
        return oidcLogoutSuccessHandler;
    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthenticationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }

    private CustomOAuth2LoginAuthenticationFilter customOAuth2LoginAuthenticationFilter() {
        CustomOAuth2LoginAuthenticationFilter customOAuth2LoginAuthenticationFilter = new CustomOAuth2LoginAuthenticationFilter(oAuth2AuthorizedClientManager, oAuth2AuthorizedClientRepository);
        customOAuth2LoginAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });
        return customOAuth2LoginAuthenticationFilter;
    }
}
