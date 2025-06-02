package io.security.oauth2.springsecurityoauth2.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class TestController {
    private final ClientRegistrationRepository clientRegistrationRepository;
    
    @GetMapping
    public String test() {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak1");

        System.out.println("clientId: " + clientRegistration.getClientId());
        System.out.println("redirectUri: " + clientRegistration.getRedirectUri());

        return "test";
    }

    /**
     * 공식 문서에 따른 사용자 정보 요청 -> 3단계라고 볼 수 있음(OAuth2 방식)
     */
    @GetMapping("/user")
    public OAuth2User user(String accessToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak1");
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        OAuth2UserRequest oauth2UserRequest = new OAuth2UserRequest(clientRegistration, oauth2AccessToken);
        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oauth2User = defaultOAuth2UserService.loadUser(oauth2UserRequest);

        return oauth2User;
    }

    /**
     * 공식 문서에 따른 사용자 정보 요청 -> 3단계라고 볼 수 있음(OIDC 방식)
     */
    @GetMapping("/oidc")
    public OAuth2User oidc(String accessToken, String idToken) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak1");
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put(IdTokenClaimNames.ISS, "https://localhost:80/realms/oauth2");
        idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
        idTokenClaims.put("preferred_username", "user");

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims);

        OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration, oauth2AccessToken, oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();
        OAuth2User oidcUser = oidcUserService.loadUser(oidcUserRequest);

        return oidcUser;
    }

    @GetMapping("/user/authentication")
    public OAuth2User user(Authentication authentication) {
        // OAuth2AuthenticationToken oauth2AuthenticationToken1 = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken oauth2AuthenticationToken2 = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauth2AuthenticationToken2.getPrincipal();
        return oAuth2User;
    }

    @GetMapping("/user/authentication/oauth2User")
    public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oauth2User) {
        System.out.println("oauth2User: " + oauth2User);
        return oauth2User;
    }

    @GetMapping("/user/authentication/oidcUser")
    public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        System.out.println("oidcUser: " + oidcUser);
        return oidcUser;
    }
}
