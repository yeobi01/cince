package com.skku.cince.infrastructure.security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;
    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;

    public JwtTokenProvider(
            @Value("${jwt.secret:your-default-secret-key-must-be-at-least-256-bits}") String secret,
            @Value("${jwt.access-token-validity:3600000}") long accessTokenValidity,  // 1시간
            @Value("${jwt.refresh-token-validity:604800000}") long refreshTokenValidity  // 7일
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessTokenValidityInMilliseconds = accessTokenValidity;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidity;
    }

    /**
     * Access Token 생성
     */
    public String createAccessToken(Authentication authentication) {
        String username = authentication.getName();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(username)
                .claim("auth", authorities)
                .claim("type", "access")
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 사용자명으로 Access Token 생성
     */
    public String createAccessToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(username)
                .claim("auth", "ROLE_USER")  // 기본 권한
                .claim("type", "access")
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Refresh Token 생성
     */
    public String createRefreshToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + refreshTokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(username)
                .claim("type", "refresh")
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 토큰에서 사용자명 추출
     */
    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch (JwtException e) {
            log.error("토큰에서 사용자명 추출 실패: {}", e.getMessage());
            throw new JwtException("Invalid token", e);
        }
    }

    /**
     * 토큰에서 권한 정보 추출
     */
    public String getAuthoritiesFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.get("auth", String.class);
        } catch (JwtException e) {
            log.error("토큰에서 권한 추출 실패: {}", e.getMessage());
            return "ROLE_USER";  // 기본 권한 반환
        }
    }

    /**
     * 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException e) {
            log.error("잘못된 JWT 서명입니다.");
        } catch (MalformedJwtException e) {
            log.error("잘못된 JWT 토큰입니다.");
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 잘못되었습니다.");
        } catch (Exception e) {
            log.error("JWT 토큰 검증 중 오류 발생: {}", e.getMessage());
        }
        return false;
    }

    /**
     * 토큰 만료 시간 확인
     */
    public Date getExpirationDateFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getExpiration();
        } catch (JwtException e) {
            log.error("토큰에서 만료시간 추출 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 토큰이 만료되었는지 확인
     */
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration != null && expiration.before(new Date());
    }

    /**
     * 토큰 타입 확인 (access/refresh)
     */
    public String getTokenType(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.get("type", String.class);
        } catch (JwtException e) {
            log.error("토큰 타입 추출 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Access Token인지 확인
     */
    public boolean isAccessToken(String token) {
        return "access".equals(getTokenType(token));
    }

    /**
     * 1. signin, signup 을 했다면, atoken, rtoken을 발급해주고
     * 2. 모든 요청에서는 atoken 기반으로 체크를 하는데, (atoken은 TTL이 짧게 해서 반복적으로 장기간 사용하지 않도록 한다)
     * 3. access token (ttl을 짧게 사용하라 - 1분) vs refresh token (1일, 10일, 30일, 90일 ..)
     * 4. rtoken을 가지고 다시 요청을 하면 내가 atoken을 다시 내려줄게
     * 5. atoken 받았으니 다시 쓰는거고,
     *
     * Refresh Token인지 확인
     */
    public boolean isRefreshToken(String token) {
        return "refresh".equals(getTokenType(token));
    }

    /**
     * 토큰 갱신 (Refresh Token으로 새로운 Access Token 생성)
     */
    public String refreshAccessToken(String refreshToken) {
        if (validateToken(refreshToken) && isRefreshToken(refreshToken)) {
            String username = getUsernameFromToken(refreshToken);
            return createAccessToken(username);
        }
        throw new JwtException("Invalid refresh token");
    }
}