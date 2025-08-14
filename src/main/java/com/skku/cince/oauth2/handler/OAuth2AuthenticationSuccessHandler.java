package com.skku.cince.oauth2.handler;

import com.skku.cince.infrastructure.security.JwtTokenProvider;
import com.skku.cince.infrastructure.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    private final CookieUtil cookieUtil;

    @Value("${jwt.access-token-expiry:3600000}")
    private long accessTokenValidityInMilliseconds;

    @Value("${jwt.refresh-token-expiry:604800000}")
    private long refreshTokenValidityInMilliseconds;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        Cookie accessTokenCookie = cookieUtil.createCookie("accessToken", accessToken, (int) (accessTokenValidityInMilliseconds / 1000));
        response.addCookie(accessTokenCookie);

        String refreshToken = jwtTokenProvider.createRefreshToken(email);
        Cookie refreshTokenCookie = cookieUtil.createCookie("refreshToken", refreshToken, (int) (refreshTokenValidityInMilliseconds / 1000));
        refreshTokenCookie.setHttpOnly(true);
        response.addCookie(refreshTokenCookie);

        redisTemplate.opsForValue().set(email, refreshToken, refreshTokenValidityInMilliseconds, TimeUnit.MILLISECONDS);
        log.info("Permanent Refresh Token stored in Redis for {}. TTL: {}s", email, refreshTokenValidityInMilliseconds / 1000);

        String targetUrl = createRedirectUrl();
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String createRedirectUrl() {
        // 프론트엔드에서 로그인 성공 후 이동할 페이지
        return UriComponentsBuilder.fromUriString("http://localhost:8080/oauth/redirected")
                .build().toUriString();
    }
}
