package com.skku.cince.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class AdditionalInfoRequestDto {
    private String phoneNumber;
    // 서비스에 따라 필요한 정보를 해당 Dto에 기입
}
