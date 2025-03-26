package ServerLessArch.Be.login.oauth;

import ServerLessArch.Be.user.domain.User;
import ServerLessArch.Be.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 미완성인 정보를 받아 회원가입을 완료하면 안됨, 추가 정보를 받을 예정
 * DB에 저장하지 않고 어떻게 기존 정보를 유지한채 추가 정보를 받는가?
 * 로그인에 성공하면 HttpSession이나 SpringSecurity ContextHolder에 정보를 저장할 수 있음
 * 따라서 추가 정보를 더 받으려면 위에서 꺼내면 됨
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceOAuth2 extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    /**
     * 해당 절차를 걸쳐 인증을 받은 사용자 정보는 Oauth2User에 포함된다.
     * @param userRequest
     * @return
     * @throws OAuth2AuthenticationException
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("구글 인증 성공");
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // 구글은 sub, 네이버는 id 등 각 플랫폼 마다 다른 id로 고유한 유저를 구분한다.
        String userNameAttribute = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // oauth를 제공하는 서비스마다 제공 방식이 조금씩 다르다. 이를 일관성있게 처리하기 위해 중간 변환 객체를 사용한다.
        OAuth2Attribute oAuth2Attribute =
                OAuth2Attribute.of(registrationId, userNameAttribute, oAuth2User.getAttributes());
        String name = oAuth2User.getAttribute("name");

        // oauth에서 받은 정보를 map 구조를 통해 생성
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();
        memberAttribute.put("name", name);
        // 사용자 email(또는 id) 정보를 가져온다.
        String email = (String) memberAttribute.get("email");
        // 이메일로 가입된 회원인지 조회한다.
        User findMember = userRepository.findUserByEmail(email).orElse(null);
        if (findMember == null) {
            // 회원이 존재하지 않을경우, memberAttribute의 exist 값을 false로 넣어준다.
            log.warn("회원 존재하지 않음");
            memberAttribute.put("exist", false);
            // 회원의 권한(회원이 존재하지 않으므로 기본권한인 ROLE_USER를 넣어준다), 회원속성, 속성이름을 이용해 DefaultOAuth2User 객체를 생성해 반환한다.
            return new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_FIRST_LOGIN")),
                    memberAttribute, "email");
        }

        log.info("멤버가 존재 멤버 : {}",memberAttribute.get("name"));
        // 회원이 존재할경우, memberAttribute의 exist 값을 true로 넣어준다.
        memberAttribute.put("exist", true);
        // 여러 개의 권한을 스트리밍해서 SimpleGrantedAuthority로 변환
        Set<GrantedAuthority> authorities = findMember.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // ROLE_ prefix 붙이기
                .collect(Collectors.toSet());
        // 회원의 권한과, 회원속성, 속성이름을 이용해 DefaultOAuth2User 객체를 생성해 반환한다.
        return new DefaultOAuth2User(authorities, memberAttribute, "email");
    }
}
