package com.rm.spring.component;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public abstract class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 사용자 정보를 데이터베이스 또는 다른 저장소에서 가져와서 UsualUserDetails 객체를 반환
        // 사용자를 찾지 못하면 UsernameNotFoundException을 던질 수 있음
        // 예를 들어, 사용자 정보를 데이터베이스에서 가져오는 코드를 작성
        // ...
        return null;
    }
}
