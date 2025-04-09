package ServerLessArch.Be.login.oauth.filter;

import ServerLessArch.Be.login.jwt.JwtUtil;
import ServerLessArch.Be.login.dto.SecurityUserDto;
import ServerLessArch.Be.user.domain.User;
import ServerLessArch.Be.user.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2JwtAuthFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    /**
     *     token을 포함하는 api 요청은 재발급 이슈가 있기 때문에 필터를 적용시키지 않음
     *     명시되지 않은 url의 경우 로그인 화면으로 리디렉션됨
     *     아래 doFilter 설정 때문에 token url은 bearer를 붙이지 않아도 됨, 근데 이 설정이 쓸모 있는지는 모르겠음
     *     2025.04.10 /test와 같이 인증 절차가 필요 없는 절차에도 인증 토큰이 있어야하는 상황이 발생, 따라서 test도 아래 dofilterInternal를 스킵하게 설정
     *     이와 같이 예외적으로 처리가 필요한 경로는 || 로 추가하면 될 듯
      */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().contains("token") || request.getRequestURI().contains("test");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request Header에서 AccessToken을 가져온다.
        String atc = request.getHeader("Authorization");

        /**
         *   2. Bearer 토큰이 없거나 잘못된 형식이면 다음 필터로 넘긴다 -> 그래서 Bearer를 붙여도 안됐음, 이전 코드는 hasNext 뿐이었음
         *   앞부분이 토큰이 없는 부분을 처리하는 것, 그리고 뒷 부분이 Bearer를 검증하는 것
          */
        if (!StringUtils.hasText(atc) || !atc.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. "Bearer "를 제거하고 순수 토큰만 추출
        String token = atc.substring(7);

        // AccessToken을 검증하고, 만료되었을경우 예외를 발생시킨다. 필터는 DispatcherServlet보다 앞에 존재하고, spring에서 예외를 처리해주는 HandlerInterceptor security context안에 존재하기 때문에
        // 필터에서 발생하는 예외를 처리할 수 없다. 따라서 예외 발생 시 401로 처리한다.
        if (!jwtUtil.verifyToken(token)) {
            throw new JwtException("Access Token 만료!");
        }

        // AccessToken의 값이 있고, 유효한 경우에 진행한다.
        if (jwtUtil.verifyToken(token)) {
            // AccessToken 내부의 payload에 있는 email로 user를 조회한다. 없다면 예외를 발생시킨다 -> 정상 케이스가 아님
            User findMember = userRepository.findUserByEmail(jwtUtil.getUid(token))
                    .orElseThrow(IllegalStateException::new);

            // SecurityContext에 등록할 User 객체를 만들어준다.
            SecurityUserDto userDto = SecurityUserDto.builder()
                    .memberNo(findMember.getId())
                    .email(findMember.getEmail())
                    .role("ROLE_".concat(findMember.getRole()))
                    .build();

            // SecurityContext에 인증 객체를 등록해준다.
            Authentication auth = getAuthentication(userDto);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }

    public Authentication getAuthentication(SecurityUserDto member) {
        return new UsernamePasswordAuthenticationToken(member, "",
                List.of(new SimpleGrantedAuthority(member.getRole())));
    }
    }


