package com.skku.cince.oauth2.filter;

import com.skku.cince.infrastructure.security.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = resolveToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            String userEmail = jwtTokenProvider.getUsernameFromToken(token);
            String role = jwtTokenProvider.getAuthoritiesFromToken(token);

            List<GrantedAuthority> authorities = Arrays.stream(role.split(","))
                    .map(String::trim) // 각 문자열의 앞뒤 공백 제거
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // userEmail 위치에는 컨트롤러에서 필요한 dto 스펙에 따라 하면 될거 같은데?
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    userEmail, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)                      // Cookie[]를 Stream<Cookie>으로 변환
                .filter(cookie -> "accessToken".equals(cookie.getName())) // 이름이 "accessToken"인 쿠키만 필터링
                .map(Cookie::getValue)                     // 쿠키의 값(토큰)을 추출
                .findFirst()                               // 필터링된 요소 중 첫 번째 것을 Optional<String>으로 반환
                .orElse(null);
    }
}
