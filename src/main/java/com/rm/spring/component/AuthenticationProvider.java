package com.rm.spring.component;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {
    /**
     * 사용자의 인증을 처리하는 메서드입니다.
     * @param authentication 사용자가 제공한 자격 증명 (사용자 이름과 비밀번호)을 포함한 인증 객체
     * @return 인증 성공 시, 사용자 정보와 권한을 포함한 새로운 인증 객체
     * @throws AuthenticationException 인증 실패 또는 예외 발생 시
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 사용자의 인증을 처리하고 성공하면 새로운 인증 객체를 반환합니다.
        // 실패할 경우 AuthenticationException을 throw하거나 null을 반환할 수 있습니다.
        return null;
    }

    /**
     * 이 AuthenticationProvider가 지원하는 인증 토큰 클래스를 지정합니다.
     * @param authentication 인증 토큰 클래스
     * @return 이 인증 프로바이더가 해당 인증 토큰 클래스를 지원하면 true, 그렇지 않으면 false
     */
    @Override
    public boolean supports(Class<?> authentication) {
        // 이 메서드에서는 이 AuthenticationProvider가 어떤 인증 토큰 클래스를 지원할지 지정합니다.
        return false;
    }
}
