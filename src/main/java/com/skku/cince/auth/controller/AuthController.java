package com.skku.cince.auth.controller;

import com.skku.cince.auth.dto.AdditionalInfoRequestDto;
import com.skku.cince.auth.service.AuthService;
import com.skku.cince.infrastructure.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final CookieUtil cookieUtil;

    @PostMapping("/signup/additional-info")
    public ResponseEntity<Void> completeSignUp(
            @AuthenticationPrincipal String userEmail,
            @Valid @RequestBody AdditionalInfoRequestDto requestDto,
            HttpServletResponse response) {

        String accessToken = authService.completeSignUp(userEmail, requestDto);
        Cookie accessTokenCookie = cookieUtil.createAccessTokenCookie(accessToken);

        response.addCookie(accessTokenCookie);

        return ResponseEntity.ok().build();
    }

}
