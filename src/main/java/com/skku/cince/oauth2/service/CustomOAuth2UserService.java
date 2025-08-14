package com.skku.cince.oauth2.service;

import com.skku.cince.oauth2.entity.ProviderType;
import com.skku.cince.oauth2.info.OAuth2UserInfo;
import com.skku.cince.oauth2.info.OAuth2UserInfoFactory;
import com.skku.cince.user.entity.User;
import com.skku.cince.user.entity.UserRole;
import com.skku.cince.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        OAuth2User oAuth2User = super.loadUser(userRequest);
        ProviderType registrationId = ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());
        if (oAuth2UserInfo.getEmail() == null) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider.");
        }
        User user = saveOrUpdateUser(oAuth2UserInfo);

//        String userNameAttributeName = userRequest.getClientRegistration()
//                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        String userEmailAttributeName = "email"; // email을 jwt sub에 넣기 위함
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleCode())), // DB 에서 조회한 role 을 기반으로 권한을 부여
                oAuth2UserInfo.getAttributes(), //  OAuth 2.0 제공자로부터 받은 원본 사용자 정보를 그대로
                userEmailAttributeName // 사용자를 식별할 키가 무엇인지
        );
    }

    private User saveOrUpdateUser(OAuth2UserInfo oAuth2UserInfo){
        User user = userRepository.findByEmail(oAuth2UserInfo.getEmail())
                .map(entity -> entity.update(oAuth2UserInfo.getName(), oAuth2UserInfo.getPicture()))
                .orElseGet(() -> createUser(oAuth2UserInfo));
        return userRepository.save(user);
    }

    private User createUser(OAuth2UserInfo oAuth2UserInfo) {
        return User.builder()
                .email(oAuth2UserInfo.getEmail())
                .name(oAuth2UserInfo.getName())
                .picture(oAuth2UserInfo.getPicture())
                .role(UserRole.GUEST) // 기본 role = ROLE_GUEST
                .build();
    }
}
