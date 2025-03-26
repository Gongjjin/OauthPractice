package ServerLessArch.Be.login.oauth.handler;

import ServerLessArch.Be.login.jwt.JwtUtil;
import ServerLessArch.Be.login.oauth.filter.GeneratedToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;

    // Filter chain을 뺐더니 해결 됨, 왜 호출되지 않다가 호출되는 것인가 ?
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 인증 성공 후 authentication에서 oauth2user를 추출 -> 해당 객체는 loadUser해서 뽑아  온 정보가 contextHolder에 저장되어 있던 것임
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        log.info(oAuth2User.getName());
        String email = oAuth2User.getAttribute("email");
        String provider = oAuth2User.getAttribute("provider");
        // CustomOAuth2UserService에서 셋팅한 로그인한 회원 존재 여부를 가져온다.
        boolean isExist = oAuth2User.getAttribute("exist");
        // OAuth2User로 부터 Role을 얻어온다.
        String role = "BASIC";
        /**
        * 회원이 존재한다면 accessToken을 검증하고, 이가 유효한다면 그대로 진행
         * 회원이 존재하지만 accessToken이 유효하지 않다면 access + refresh를 동시에 발급
         */
        if (isExist) {
            /**
             * 회원이 존재하면 액세스 토큰과 리프래시 토큰을 발급한다
             * 리프레시 토큰의 유효기간이 남은 것과는 별개로 액세스 토큰을 요청할 때 마다 리프레시 토큰도 발급한다.
             */
            GeneratedToken token = jwtUtil.generateToken(email,role);
            String AccessToken = token.getAccessToken();
            String RefreshToken = token.getRefreshToken();
            setResponseToJson(response,AccessToken,RefreshToken);
        } else {
            // 회원가입 페이지로 리다이렉트 시킨다.
            String name = oAuth2User.getAttribute("name");
            name = name.replace(" ","");
            String redirectUrl = "http://localhost:8080/complete-registration.html?name=" + URLEncoder.encode(name, "UTF-8") +
                    "&email=" + URLEncoder.encode(email, "UTF-8")+("&role=")+URLEncoder.encode(role,"UTF-8");
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        }
    }

    private void setResponseToJson(HttpServletResponse response, String AccessToken, String RefreshToken) throws IOException {
        //json으로 전달, 클라이언트에서 알아서 추출 후 사용
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"accessToken\": \"" + AccessToken + "\", \"refreshToken\": \"" + RefreshToken + "\"}");
    }
    }
