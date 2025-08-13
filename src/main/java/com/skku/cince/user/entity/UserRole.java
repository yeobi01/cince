package com.skku.cince.user.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum UserRole {
    GUEST("ROLE_GUEST", "게스트 권한"),
    USER("ROLE_USER", "일반 사용자 권한"),
    ADMIN("ROLE_ADMIN", "관리자 권한");

    private final String code;
    private final String displayName;
}