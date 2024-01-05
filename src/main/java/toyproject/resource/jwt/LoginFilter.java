package toyproject.resource.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import toyproject.resource.dto.CustomUserDetails;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // JWTUtil을 주입함 로그인시 발급하여 응답해주면됨
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
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

    // 로그인 성공 시 JWT를 발급받을 수 있도록 함
    @Override
    public void successfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain, Authentication authentication) {

        /*
            UserDetails -> User 객체를 알아내기 위함
            authentication의 getPrincipal로 받아옴
        */
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        String username = customUserDetails.getUsername();

        // 권한 받아오기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends  GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 권한을 통해 JWT를 반환받음
        String token = jwtUtil.createJWT(username, role, 60*60*10L);

        // Response에 담아줌 - RFC 7235 정의 (http 인증방식)
        httpServletResponse.addHeader("Authorization", "Bearer " + token);

        //System.out.println("Auth Success");
    }

    @Override
    public void unsuccessfulAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException failed) {

        httpServletResponse.setStatus(401);

        //System.out.println("Auth Fail");
    }

}
