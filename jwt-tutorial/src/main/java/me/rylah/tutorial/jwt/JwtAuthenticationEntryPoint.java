package me.rylah.tutorial.jwt;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    // 유효한 자격 증명을 제공하지 않고 접근하려고 할 때 에러 출력
    @Override
    public void commence(HttpServletRequest request, 
                         HttpServletResponse response, 
                         AuthenticationException authException) throws IOException, ServletException {
        // 401 Unauthorized Error
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
