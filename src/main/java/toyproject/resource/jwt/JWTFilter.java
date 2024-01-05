package toyproject.resource.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import toyproject.resource.dto.CustomUserDetails;
import toyproject.resource.entity.UserEntity;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    // JWTUtil에서 JWT 검증 메소드를 불러옴
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // 토큰 검증
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 Authorization 헤더 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더의 null 여부 검증
        if (authorization == null || !authorization.startsWith("Bearer")) {

            System.out.println("NULL TOKEN");
            filterChain.doFilter(request, response);

            return;
        }

        System.out.println("Authorization NOW");

        // 순수한 토큰만을 획득함
        String token = authorization.split(" ")[1];

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("TOKEN EXPIRED");
            filterChain.doFilter(request, response);

            return;
        }

        // username, role을 token에서 받아옴
        String username = jwtUtil.getUsername(token);
        String userrole = jwtUtil.getRole(token);

        // userEntity를 통해 얻어온 값을 설정함
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(userrole);
        // 임시 비밀번호를 설정함
        userEntity.setPassword("temppassword");

        // UserDetails에 유저 정보 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성 - userDetails로 만듦
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // context에 해당 유저를 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
