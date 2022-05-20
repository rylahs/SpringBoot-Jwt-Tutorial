package me.rylah.tutorial.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rylah.tutorial.jwt.JwtAccessDeniedHandler;
import me.rylah.tutorial.jwt.JwtAuthenticationEntryPoint;
import me.rylah.tutorial.jwt.JwtSecurityConfig;
import me.rylah.tutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@EnableWebSecurity // 기본적인 웹 보안 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) // 이후에 @PreAuthorize라는 애너테이션을 메서드 단위로 사용하기 위해 적용합니다.
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 1) WebSecurityConfigurer implements
    // 2) WebSecurityConfigurerAdapter extends

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;


    @Override
    protected void configure(HttpSecurity http) throws Exception { // httpSecurity를 수정할 수 있게 configure 메서드를 오버라이드 합니다.
        http
                .csrf().disable() // 토큰 방식을 사용할 것이기 때문에 csrf 설정을 disable 시킵니다.
                .exceptionHandling() // JWT를 다루는 EntryPoint와 Handler를 추가해줍니다.
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and() // h2-console을 위한 설정을 추가합니다.
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()// 토큰을 사용하기 때문에 세션을 사용하지 않도록 STATELESS로 설정합니다.
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll() // 가입과 로그인시에도 토큰 없이 접근할 수 있게 합니다.
                .antMatchers("/api/signup").permitAll()// "/api/hello"에는 모두가 접근할 수 있게 합니다.

                .anyRequest().authenticated() // 나머지 모든 요청에 대해서는 인증된 사용자만 접근할 수 있게 합니다.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider)); // JwtSecurityConfig 클래스에 구현한 내용도 설정으로 적용합니다.
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/h2-console/**", "/favicon.ico"); // 웹에서 h2-console 하위 리소스에 권한 없이 접근할 수 있게 수정해줍니다.
    }

    @Bean
    public PasswordEncoder passwordEncoder() { // 가입, 로그인 시 사용할 PasswordEncoder를 빈으로 등록합니다.
        return new BCryptPasswordEncoder();
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
