package com.skku.cince.auth.service;

import com.skku.cince.auth.dto.AdditionalInfoRequestDto;
import com.skku.cince.infrastructure.exception.UserNotFoundException;
import com.skku.cince.infrastructure.security.JwtTokenProvider;
import com.skku.cince.user.entity.User;
import com.skku.cince.user.entity.UserRole;
import com.skku.cince.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    public String completeSignUp(String userEmail, AdditionalInfoRequestDto requestDto){
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("해당 이메일을 가진 사용자를 찾을 수 없습니다: " + userEmail));

        user.updatePhoneNumber(requestDto.getPhoneNumber());
        user.updateRole(UserRole.USER);

//        여기서 authentication 수정하는 건 별로인가?
//        String accessToken = jwtTokenProvider.createAccessToken(authentication);
//        아래처럼 name으로 만드는게 아니라 그냥 User 객체 자체를 던지면 안되는가?
        String accessToken = jwtTokenProvider.createAccessToken(user.getName());

        return accessToken;
    }
}
