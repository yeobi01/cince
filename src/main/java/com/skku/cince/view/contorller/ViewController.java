package com.skku.cince.view.contorller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class ViewController {

    @GetMapping("/")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/oauth/redirected")
    public String afterLoginPage() {
        return "after_login";
    }
}
