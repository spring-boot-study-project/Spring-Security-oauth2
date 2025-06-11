package com.springboot.security_resoource_server.convert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PREFIX = "ROLE_";

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> convert(final Jwt jwt) {

        String scopes = jwt.getClaimAsString("scope");
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

        if (scopes == null || realmAccess == null) {
            return Collections.EMPTY_LIST;
        }

        Collection<GrantedAuthority> authorities1 = Arrays.stream(scopes.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        Collection<GrantedAuthority> authorities2 = ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities1.addAll(authorities2);

        return authorities1;
    }
}