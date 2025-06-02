package io.security.oauth2.springsecurityoauth2.controller;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

    private Duration clockSkew = Duration.ofSeconds(3600);

    private Clock clock = Clock.systemUTC();

    /**
     * Owner Password 방식으로 인증 처리 구현현
     * @param model
     * @param request
     * @param response
     * @return
     */
    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response) {

        // 이 시점에서는 authentication 객체가 null이 될 수 없다. -> mvc 쪽으로 넘어오게 될 경우 인증이 되어있지 않으면 익명 사용자로
        // 객체가 생성되어서 넘어오기 때문에 null이 될 수 없지만 filter 쪽은 null에 대한 처리를 해줘야 된다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository
                    .saveAuthorizedClient(authorizedClient, principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            System.out.println("authorizedClient = " + authorizedClient);
            System.out.println("principal = " + principal);
            System.out.println("attributes = " + attributes);
        };

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        // 여기 위까지는 credentials 방식으로 인가 처리 -> 인증 처리는 없음

        // 권한 부여 타입을 변경하지 않고 토큰 재발급 -> 동일 인증 처리는 없음
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
                && authorizedClient.getRefreshToken() != null) {
            authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        }

        // 권한 부여 타입을 변경하고 토큰 재발급 -> 동일 인증 처리는 없음
        // if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
          
        //     ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(authorizedClient.getClientRegistration())
        //             .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        //             .build();
         
        //     OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(
        //         clientRegistration, 
        //         authorizedClient.getPrincipalName(),
        //         authorizedClient.getAccessToken(), 
        //         authorizedClient.getRefreshToken()
        //     );

        //     OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(oAuth2AuthorizedClient)
        //             .principal(authentication)
        //             .attribute(HttpServletRequest.class.getName(), request)
        //             .attribute(HttpServletResponse.class.getName(), response)
        //             .build();

        //     authorizedClient = oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        // }

        // password 방식으로 인증 처리
        // if (authorizedClient != null) {
        //     OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
        //     ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
        //     OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        //     OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
        //     OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

        //     SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        //     authorityMapper.setPrefix("SYSTEM_");
        //     Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

        //     OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User,
        //             grantedAuthorities, clientRegistration.getRegistrationId());

        //     SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

        //     model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
        // }

        model.addAttribute("AccessToken", authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("RefreshToken", authorizedClient.getRefreshToken().getTokenValue());

        return "home";

    }

    @GetMapping("/v2/oauth2Login")
    public String oauth2LoginV2(
        Model model,
        @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient oAuth2AuthorizedClient,
        HttpServletRequest request, 
        HttpServletResponse response
    ) {
        if (oAuth2AuthorizedClient != null) {

            OAuth2AuthorizationSuccessHandler authorizationSuccessHandler = (authorizedClient, authentication,
                    attributes) -> oAuth2AuthorizedClientRepository
                            .saveAuthorizedClient(authorizedClient, authentication,
                                    (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                                    (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);

            ClientRegistration clientRegistration = oAuth2AuthorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();

            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2User oauth2User = oAuth2UserService
                    .loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient.getClientRegistration(), accessToken));

            SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
            Collection<? extends GrantedAuthority> authorities = simpleAuthorityMapper
                    .mapAuthorities(oauth2User.getAuthorities());
            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oauth2User, authorities,
                    clientRegistration.getRegistrationId());
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

            authorizationSuccessHandler.onAuthorizationSuccess(oAuth2AuthorizedClient, oAuth2AuthenticationToken,
                    createAttributes(request, response));
            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);

        }

        return "home";
    }

    private static Map<String, Object> createAttributes(
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse
    ) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), servletRequest);
        attributes.put(HttpServletResponse.class.getName(), servletResponse);
        return attributes;
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletResponse response, HttpServletRequest request) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }
}
