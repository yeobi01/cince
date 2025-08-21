package com.skku.cince.infrastructure.util;

import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    @Value("${jwt.access-token-expiry:3600000}")
    private long accessTokenValidityInMilliseconds;

    public Cookie createCookie(String key, String value, int maxAge) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(maxAge);
        cookie.setPath("/"); // 쿠키가 전송될 경로를 전체 경로로 설정
        // cookie.setSecure(true);
        return cookie;
    }

    public Cookie createAccessTokenCookie(String accessToken) {

        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setPath("/"); // 모든 경로에서 쿠키 사용
        accessTokenCookie.setMaxAge((int) (accessTokenValidityInMilliseconds / 1000)); // 쿠키 만료 시간 설정 (초 단위)
        accessTokenCookie.setHttpOnly(true);

        return accessTokenCookie;
    }
}
