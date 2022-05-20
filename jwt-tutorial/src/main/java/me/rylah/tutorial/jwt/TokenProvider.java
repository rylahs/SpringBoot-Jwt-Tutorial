package me.rylah.tutorial.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long expiredTime;
    private SecretKey key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expired-time}") long expiredTime
    ) {
        this.secret = secret;
        this.expiredTime = expiredTime;
    }

    @Override
    public void afterPropertiesSet() {
        byte[] decoded = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(decoded);
    }

    // 인증 정보(Authentication) 객체를 전달받아 인증, 권한 정보와 토큰 고유의 정보(알고리즘, 만료시간) 합쳐 토큰을 생성합니다.
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date expiration = new Date(now + this.expiredTime);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(expiration)
                .compact();
    }

    // JwtParser를 이용해 토큰을 파싱하면 Claims라는 객체를 얻게 되고, 이 객체에서 인증 정보를 다시 꺼내올 수 있습니다.

    public Authentication getAuthentication(String token) {
        JwtParser jwtParser = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build();

        Claims claims = jwtParser
                .parseClaimsJws(token)
                .getBody();

        // 꺼낸 정보들을 가지고 다시 User(UserDetails의 구현체, 스프링 시큐리티 제공) 객체를 생성해서 Authentication 객체로 반환해주면 됩니다.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // JwtParser를 이용해 Claims객체로 파싱하는 과정에서 여러 가지 예외가 발생할 수 있습니다.
    // 이 때 발생하는 에러들을 적절하게 예외처리해주면 됩니다.
    public boolean validateToken(String token) {
        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
        try {
            jwtParser.parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}