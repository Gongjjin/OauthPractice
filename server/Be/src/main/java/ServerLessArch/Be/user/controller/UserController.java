package ServerLessArch.Be.user.controller;
import ServerLessArch.Be.login.dto.LoginDTO;
import ServerLessArch.Be.login.dto.StatusResponseDto;
import ServerLessArch.Be.login.dto.TokenResponseStatus;
import ServerLessArch.Be.login.jwt.JwtUtil;
import ServerLessArch.Be.login.redis.RefreshToken;
import ServerLessArch.Be.login.redis.RefreshTokenRepository;
import ServerLessArch.Be.login.redis.RefreshTokenService;
import ServerLessArch.Be.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping()
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final RefreshTokenService tokenService;
    private final RefreshTokenRepository tokenRepository;
    private final JwtUtil jwtUtil;

    @PostMapping("/join")
    public String join(@ModelAttribute LoginDTO loginDTO) {
        userService.joinUser(loginDTO);
        return "redirect:http://localhost:8080/login.html";
    }

    @PostMapping("token/logout")
    public ResponseEntity<StatusResponseDto> logout(@RequestHeader("Authorization") final String accessToken) {
        tokenService.removeRefreshToken(accessToken);
        return ResponseEntity.ok(StatusResponseDto.addStatus(200));
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<TokenResponseStatus> refresh(@RequestHeader("Authorization") final String accessToken) {
        log.info("액세스 토큰 : {}", accessToken);
        Optional<RefreshToken> refreshToken = tokenRepository.findByAccessToken(accessToken);
        log.info("리프레시 토큰 : {}",refreshToken.get().getRefreshToken());
        // RefreshToken이 존재하고 유효하다면 실행
        if (refreshToken.isPresent() && jwtUtil.verifyRefreshToken(refreshToken.get().getRefreshToken())) {
            // RefreshToken 객체를 꺼내온다.
            RefreshToken resultToken = refreshToken.get();
            // 권한과 아이디를 추출해 새로운 액세스토큰을 만든다.
            String newAccessToken = jwtUtil.generateAccessToken(resultToken.getId(), jwtUtil.getRole(resultToken.getRefreshToken()));
            // 액세스 토큰의 값을 수정해준다.
            resultToken.updateAccessToken(newAccessToken);
            tokenRepository.save(resultToken);
            // 새로운 액세스 토큰을 반환해준다.
            return ResponseEntity.ok(TokenResponseStatus.addStatus(200, newAccessToken));
        }

        return ResponseEntity.badRequest().body(TokenResponseStatus.addStatus(400, null));
    }

    /**
     *
     * @return
     */
    @GetMapping("/test")
    public String testToParse(){
        return "hello";
    }
}
