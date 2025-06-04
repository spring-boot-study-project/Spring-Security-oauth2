package com.springboot.security_resoource_server.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    
    @GetMapping("/")
    @PreAuthorize("hasAuthority('SCOPE_photo')")
    public Authentication index(Authentication authentication) {
        return authentication;
    }
}
