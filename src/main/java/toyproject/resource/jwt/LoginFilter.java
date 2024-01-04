package toyproject.resource.jwt;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {

        // id, pw 추출
        String username = obtainUsername(httpServletRequest);
        String password = obtainPassword(httpServletRequest);

        System.out.println(username);

        // DTO 역할의 TOKEN
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // manager에게 id,pw 검증 결과를 return 받게끔함
        return authenticationManager.authenticate(authToken);
    }

    @Override
    public void successfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain, Authentication authentication) {

    }

    @Override
    public void unsuccessfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException failed) {

    }

}
