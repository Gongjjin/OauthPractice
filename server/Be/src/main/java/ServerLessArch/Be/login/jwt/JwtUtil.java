package ServerLessArch.Be.login.jwt;

import ServerLessArch.Be.login.oauth.filter.GeneratedToken;
import ServerLessArch.Be.login.redis.RefreshTokenService;
import ServerLessArch.Be.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;


/**
 * JWT 토큰 생성 및 검증을 담당하는 클래스
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtUtil {
    @Value("${jwt.secretkey}")
    private String secretKey;
    @Value("${jwt.access.expiration}")
    private Long accessTokenExp;
    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExp;
    @Value("${jwt.access.header}")
    private String accessHeader;
    @Value("${jwt.refresh.header}")
    private String refreshHeader;
    private final UserRepository userRepository;
    private final RefreshTokenService tokenService;

    /**
     * 시간이 밀리초로 처리돼서 충분히 늘려서 써야함 짧게했더니 개고생
     * @param email
     * @param role
     * @return
     */
    public GeneratedToken generateToken(String email, String role) {
        // refreshToken과 accessToken을 생성한다.
        String accessToken = generateAccessToken(email, role);
        String refreshToken = generateRefreshToken(email, role);
        log.info("리프레시 토큰 {}",refreshToken);
        log.info("액세스 토큰 {}", accessToken);
        log.info(email);
        tokenService.saveTokenInfo(email, refreshToken, accessToken);
        return new GeneratedToken(accessToken, refreshToken);
    }

    public String generateRefreshToken(String email, String role) {
        Claims claims = Jwts.claims().setSubject(email);
        // 현재 시간과 날짜를 가져온다.
        Date now = new Date();
        return Jwts.builder()
                // Payload를 구성하는 속성들을 정의한다.
                .setClaims(claims)
                // 발행일자를 넣는다.
                .setIssuedAt(now)
                // 토큰의 만료일시를 설정한다.
                .setExpiration(new Date(now.getTime() + refreshTokenExp))
                // 지정된 서명 알고리즘과 비밀 키를 사용하여 토큰을 서명한다.
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String generateAccessToken(String email, String role) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("role", role);
        Date now = new Date();
        Date test = new Date(now.getTime() + accessTokenExp);
        return
                Jwts.builder()
                        // Payload를 구성하는 속성들을 정의한다.
                        .setClaims(claims)
                        // 발행일자를 넣는다.
                        .setIssuedAt(now)
                        // 토큰의 만료일시를 설정한다.
                        .setExpiration(new Date(now.getTime() + accessTokenExp))
                        // 지정된 서명 알고리즘과 비밀 키를 사용하여 토큰을 서명한다.
                        .signWith(SignatureAlgorithm.HS256, secretKey)
                        .compact();

    }

    /**
     * 리프레시와 액세스 토큰이 구분이 안됨, 두 토큰 모두 유효기간만 남아있으면 승인되는 상황
     * 액세스와 리프레시를 권한으로 구분하여 액세스 토큰만 인증에 사용되게 할 것
     * 여기서 걸렸네 리프레시가 있는데 처리가 잘못됨, 리프레시는 리프레시로 처리되게하고 액세스는 액세스로 처리되게하면 될 듯
     * @param token
     * @return
     */
    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(secretKey) // 비밀키를 설정하여 파싱한다.
                    .parseClaimsJws(token);  // 주어진 토큰을 파싱하여 Claims 객체를 얻는다.
            if(claims.getBody().get("role", String.class).isEmpty()){
                log.warn("리프레시 토큰으로 인증하려함");
                throw new RuntimeException("액세스 토큰이 아닙니다.");
            }
            // 토큰의 만료 시간과 현재 시간비교
            return claims.getBody()
                    .getExpiration()
                    .after(new Date());  // 만료 시간이 현재 시간 이후인지 확인하여 유효성 검사 결과를 반환
        } catch (Exception e) {
            return false;
        }
    }

    public boolean verifyRefreshToken(String refreshToken){
        try {
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(secretKey) // 비밀키를 설정하여 파싱한다.
                    .parseClaimsJws(refreshToken);  // 주어진 토큰을 파싱하여 Claims 객체를 얻는다.
                claims.getBody().getExpiration().after(new Date());
                return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 Email을 추출한다.
    public String getUid(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // 토큰에서 ROLE(권한)만 추출한다.
    public String getRole(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("role", String.class);
    }

}
