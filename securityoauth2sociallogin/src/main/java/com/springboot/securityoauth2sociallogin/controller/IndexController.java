package com.springboot.securityoauth2sociallogin.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.springboot.securityoauth2sociallogin.model.users.PrincipalUser;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal PrincipalUser principalUser) {

        String view = "index";

        if (principalUser != null) {

            String userName = principalUser.providerUser().getUsername();

            model.addAttribute("user", userName);
            model.addAttribute("provider", principalUser.providerUser().getProvider());
            if (!principalUser.providerUser().isCertificated())
                view = "selfcert";
        }

        return view;
    }
}
