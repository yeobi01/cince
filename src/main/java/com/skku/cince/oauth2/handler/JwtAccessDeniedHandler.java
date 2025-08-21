package com.skku.cince.oauth2.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    // 필요한 권한이 없이 접근하려 할때 403 에러 반환하도록
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            boolean isGuest = authentication.getAuthorities().stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_GUEST"));

            if (isGuest) {
                log.info("GUEST user access denied. Redirecting to additional info page.");
                response.sendRedirect("http://localhost:8080/oauth/redirected");
                return; // 리다이렉트 후 처리를 종료합니다.
            }
        }

        log.info("403 인가 에러");
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }
}