package com.skku.cince.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("")
    public ResponseEntity<Map<String, String>> getUserInfo(@AuthenticationPrincipal String userEmail) {
        // @AuthenticationPrincipal = 현재 인증된 사용자의 정보를 받아옴
        // User는 user entity가 아닌 JwtAuthenticationFilter 에서 SecurityContext에 저장한 User 객체를 의미
        if (userEmail == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not authenticated"));
        }
        return ResponseEntity.ok(Map.of("username", userEmail));
    }
}
