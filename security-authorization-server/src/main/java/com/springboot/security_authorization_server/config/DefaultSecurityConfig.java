package com.springboot.security_authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {
    @Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userDetailsService());
        
        http
			.authorizeHttpRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.formLogin(withDefaults());
        http.authenticationProvider(daoAuthenticationProvider);
		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(){

		UserDetails user = User.withUsername("user").password("{noop}1234").authorities("ROLE_USER").build();
		return new InMemoryUserDetailsManager(user);
	}
}
