package com.springboot.security_resoource_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.springboot.security_resoource_server.convert.CustomRoleConverter;

import lombok.RequiredArgsConstructor;

// import static org.springframework.security.config.Customizer.withDefaults;

// import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;

// resource server 설정 관련 클래스 파일들
// import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
// import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;


// 자동 설정 클래스 파일들
// import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    // private final OAuth2ResourceServerProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConverter());

        return http.authorizeHttpRequests(auth -> auth
                    .requestMatchers(HttpMethod.GET, "/photo/**")
                    .hasAuthority("SCOPE_photo") // 이러한 스코프 권한이 있다면 접근 가능 -> 앞에 스코프 값을 그대로 사용하고 있는데 이거 수정 가능
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(
                    jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                )
                .build();
    }

    // @Bean
    // public JwtDecoder jwtDecoder1() {
    //     return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    // }

    // @Bean
    // public JwtDecoder jwtDecoder2(){
    //     return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
    // }

    // 위의 방식에서 manager에서 자동으로 빈 설정하고 properties에서 uri를 넘겨준다.
    
    // @Bean
    // public JwtDecoder jwtDecoder3() {
    //     return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
    //             .jwsAlgorithm(SignatureAlgorithm.RS512).build();
    // }

    // 내부적으로 설정을 해주기 때문에 명시적으로 설정은 굳이 안해줘도 될듯..?
}
