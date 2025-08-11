package com.skku.cince.oauth2.user;

import com.skku.cince.oauth2.entity.ProviderType;
import com.skku.cince.oauth2.user.impl.GithubOAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case GITHUB: return new GithubOAuth2UserInfo(attributes);
            default: throw new IllegalArgumentException("Invalid Provider Type.");
        }
    }
}