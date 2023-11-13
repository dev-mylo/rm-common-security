package com.rm.spring.configuration;

import com.rm.spring.component.*;
import com.rm.spring.filter.CorsFilter;
import com.rm.spring.filter.UsernamePasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity

// component-based 방식
public abstract class SecurityConfiguration {

    @Autowired
    // AuthenticationManagerBuilder에 커스텀 인증 제공자를 설정합니다.
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new AuthenticationProvider());
    }

    @Autowired
    // CORS 설정을 위한 CorsConfigurationSource를 주입받습니다.
    CorsConfigurationSource corsConfigSource;
    @Autowired
    @Qualifier("AuthenticationManagerBean")
    // Spring Security의 인증 관리자를 주입받습니다.
    private AuthenticationManager authenticationManagerBean;
    @Bean
    // 패스워드 인코딩을 위한 BCryptPasswordEncoder를 Bean으로 등록합니다.
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * SecurityFilterChain Bean 설정
     * <p>
     * 이 메서드는 HttpSecurity 객체를 설정하여 사용자 정의 SecurityFilterChain을 생성하고 반환합니다.
     * SecurityFilterChain은 HTTP 요청이 들어올 때 적용되는 연속적인 보안 필터들의 체인입니다.
     *
     * @param http HttpSecurity 객체
     * @return 사용자 정의 SecurityFilterChain
     * @throws Exception 보안 설정 중 발생하는 예외
     */

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        configureCommon(http);
        configureCustom(http);

        return http.build(); // SecurityFilterChain 객체를 생성하고 반환합니다.
    }

    protected void configureCustom(HttpSecurity http) throws Exception {

    }

    /**
     * AuthenticationManager Bean 설정
     *
     * 이 메서드는 Spring Security의 AuthenticationManager Bean을 설정하고 반환합니다.
     * AuthenticationManager는 인증 요청을 처리하는 주요 인터페이스로, 주로 사용자 인증에 사용됩니다.
     *
     * @param authenticationConfiguration Spring Security의 기본 인증 구성 객체
     * @return 설정된 AuthenticationManager 객체
     * @throws Exception 인증 관련 설정 중 발생하는 예외
     */

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * WebSecurityCustomizer Bean 설정
     *
     * 이 메서드는 Spring Security의 WebSecurity 설정을 사용자 정의하기 위해 사용됩니다.
     * 특정 경로를 Spring Security의 필터 체인에서 제외하려면 이 방식을 사용할 수 있습니다.
     *
     * @return WebSecurityCustomizer 객체로, web.ignoring()을 사용하여 특정 경로를 필터 체인에서 제외
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
    }


//    /**
//     * AccessDeniedHandler Bean 설정
//     *
//     * 이 메서드는 사용자 정의 AccessDeniedHandler의 Bean을 생성하고 반환합니다.
//     * AccessDeniedHandler는 인증된 사용자가 권한이 없는 리소스에 접근하려고 시도할 때 호출됩니다.
//     * 이 구현에서는 403 Forbidden 응답과 함께 "FORBIDDEN" 메시지를 반환합니다.
//     *
//     * @return UsualAccessDeniedHandler의 인스턴스
//     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandler();
    }
//
//    /**
//     * UsualAuthenticationEntryPoint Bean 설정.
//     *
//     * 이 메서드는 인증되지 않은 사용자가 보호된 리소스에 접근하려 할 때 실행되는
//     * AuthenticationEntryPoint를 설정하고 반환합니다. 일반적으로 이를 통해
//     * 사용자에게 특정한 응답을 보내거나 인증 메커니즘(예: 로그인 페이지로 리다이렉트)을 시작합니다.
//     *
//     * @return UsualAuthenticationEntryPoint 객체
//     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint();
    }
//
//    /**
//     * UsualLogoutSuccessHandler Bean 설정
//     *
//     * 이 메서드는 로그아웃 성공 시 수행되는 사용자 정의 처리 로직을 위해
//     * UsualLogoutSuccessHandler의 인스턴스를 생성하고 반환합니다.
//     *
//     * UsualLogoutSuccessHandler는 LogoutSuccessHandler 인터페이스를 구현하여
//     * 로그아웃 성공 시 수행될 로직을 정의합니다. 이 Bean은 Security 설정에서
//     * 사용되어 로그아웃 성공 시 원하는 동작을 수행하게 됩니다.
//     *
//     * @return UsualLogoutSuccessHandler의 새로운 인스턴스
//     */
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new LogoutSuccessHandler();
    }
//
//    /**
//     * CORS 필터 Bean 설정
//     *
//     * 이 메서드는 사용자 정의 CORS 필터인 {@link UsualCorsFilter}의 Bean을 생성하고 반환합니다.
//     * CORS(Cross-Origin Resource Sharing)는 추가적인 HTTP 헤더를 사용하여 한 출처에서 실행 중인 웹 페이지가
//     * 다른 출처의 선택한 리소스에 접근할 수 있는 권한을 부여하도록 브라우저에 알려주는 웹 페이지와 웹 서버 간의 테크닉입니다.
//     *
//     * @return {@link UsualCorsFilter}의 인스턴스
//     */
    @Bean
    public CorsFilter usualCorsFilter() {
        return new CorsFilter(corsConfigSource);
    }
//
//    /**
//     * 사용자 인증 실패 핸들러에 대한 Bean 정의.
//     * 사용자 인증이 실패할 때 이 핸들러가 트리거됩니다.
//     *
//     * @return UsualAuthenticationFailureHandler의 인스턴스.
//     */
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new AuthenticationFailureHandler();
    }
//
//    /**
//     * 사용자 인증 성공 핸들러에 대한 Bean 정의.
//     * 사용자 인증이 성공적으로 수행될 때 이 핸들러가 트리거됩니다.
//     *
//     * @return UsaulAuthenticationSuccessHandler의 인스턴스.
//     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new AuthenticationSuccessHandler();
    }

//    @Bean
//    public UsualJWTAuthenticationFilter jwtAuthenticationFilter() {
//        return new UsualJWTAuthenticationFilter();
//    }


    @Bean
    public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() throws Exception {
        UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManagerBean);
        return filter;
    }

    // 공통 설정만을 수행하는 메서드
    protected void configureCommon(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().disable()
                .authorizeRequests()
                .antMatchers(
                        "/swagger-ui/**",
                        "/webjars/**",
                        "/v2/api-docs",
                        "/configuration/ui",
                        "/swagger-resources/**",
                        "/configuration/security",
                        "/swagger-ui.html",
                        "/webjars/**",
                        "/login")
                .permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .formLogin()
                .loginProcessingUrl("/login") // 로그인 처리 URL을 설정합니다. 기본적으로 /login 입니다.
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .and()
                .logout()
                .logoutSuccessHandler(logoutSuccessHandler())
                .and()
                .addFilterBefore(usernamePasswordAuthenticationFilter(), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

    }

}
