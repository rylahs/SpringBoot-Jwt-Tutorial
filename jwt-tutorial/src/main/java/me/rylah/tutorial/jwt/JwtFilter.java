package me.rylah.tutorial.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 토큰의 인증 정보를 SecuriyContext에 저장하는 역할 수행

        // Casting
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String jwt = resolveToken(httpServletRequest); // request에서 토큰을 받아온다.
        String requestURI = httpServletRequest.getRequestURI();

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { // 유효성 검증
            Authentication authentication = tokenProvider.getAuthentication(jwt); // 정상이면 토큰 -> Authentication 객체를 받아옴
            SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext에 Setting
            log.debug("Security Context에 '{}' 인증 정보를 저장했습니다, URI: {}", authentication.getName(), requestURI);
        } else {
            log.debug("유효한 JWT 토큰이 없습니다, URI: {}", requestURI);
        }
        chain.doFilter(request,response);
    }

    /**
     * Request Header에서 토큰 정보를 꺼내오기 위함
     * @param request
     * @return
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = ((HttpServletRequest) request).getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
