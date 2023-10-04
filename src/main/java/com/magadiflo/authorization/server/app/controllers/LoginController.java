package com.magadiflo.authorization.server.app.controllers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {
    @GetMapping(path = "/login")
    public String login() {
        return "login";
    }

    @GetMapping(path = "/logout")
    public String logout() {
        return "logout";
    }

    @PostMapping(path = "/logout")
    public String logoutOK(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.logout(logout -> logout
                .logoutSuccessUrl("login?logout")
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true));
        return "login?logout";
    }
}
