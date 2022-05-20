package me.rylah.tutorial.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    // SecurityConfigurerAdapter extends
    // TokenProvider 주입

    // JwtFilter를 이용해서 Security 로직에 필터를 등록

    private final TokenProvider tokenProvider;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        JwtFilter customFilter = new JwtFilter(tokenProvider); // JwtFiler를 등록
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
