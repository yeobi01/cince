package com.skku.cince.infrastructure.util;

import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {
    public Cookie createCookie(String key, String value, int maxAge) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(maxAge);
        cookie.setPath("/"); // 쿠키가 전송될 경로를 전체 경로로 설정
        // cookie.setSecure(true);
        return cookie;
    }
}
