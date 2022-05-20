package me.rylah.tutorial.service;

import lombok.RequiredArgsConstructor;
import me.rylah.tutorial.dto.UserDto;
import me.rylah.tutorial.entity.Authority;
import me.rylah.tutorial.entity.User;
import me.rylah.tutorial.repository.UserRepository;
import me.rylah.tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // 회원 가입
    @Transactional
    public User signup(UserDto userDto) { // DB 내에 중복 확인
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder() // 권한 정보 삽입
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder() // 유저 정보 생성
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();


        return userRepository.save(user); // 유저와 권한 정보 저장
    }

    // 유저 권한 정보를 가져오는 메소드

    // username을 파라미터로 받아서 그 기준으로 정보를 가져오는 메소드
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    // SecurityContext에 저장된 username 정보만 가져오는 메소드
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }

}
