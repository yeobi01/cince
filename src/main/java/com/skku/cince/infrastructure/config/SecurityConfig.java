package com.skku.cince.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터 체인을 활성화
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(formLogin -> formLogin.disable())
                // 1. 인가(Authorization) 설정
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/error", "/login**").permitAll()
                        .anyRequest().authenticated()
                )
                // 2. OAuth2 로그인 설정
                .oauth2Login(withDefaults()); // 기본 설정을 따릅니다. (application.yml에 설정한 내용)


        return http.build();
    }
}
