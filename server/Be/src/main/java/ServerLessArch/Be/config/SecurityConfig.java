    package ServerLessArch.Be.config;


    import ServerLessArch.Be.login.oauth.filter.JwtExceptionFilter;
    import ServerLessArch.Be.login.oauth.filter.OAuth2JwtAuthFilter;
    import ServerLessArch.Be.login.oauth.handler.OAuth2LoginFailureHandler;
    import ServerLessArch.Be.login.oauth.handler.OAuth2LoginSuccessHandler;
    import ServerLessArch.Be.login.oauth.UserServiceOAuth2;
    import lombok.RequiredArgsConstructor;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.http.HttpHeaders;
    import org.springframework.http.HttpMethod;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
    import org.springframework.web.cors.CorsConfiguration;
    import org.springframework.web.cors.CorsConfigurationSource;
    import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

    @Configuration
    @EnableWebSecurity
    @RequiredArgsConstructor
    public class SecurityConfig {
        private final UserServiceOAuth2 userService;
        private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
        private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
        private final OAuth2JwtAuthFilter oAuth2JwtAuthFilter;
        private final JwtExceptionFilter jwtExceptionFilter;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.formLogin(login -> login.disable()) // FormLogin 사용 X
                    .csrf(csrf -> csrf.disable()) // csrf 보안 사용 X
                    .httpBasic(httpBasic -> httpBasic.disable()) // httpBasic 사용 X
                    .cors(cors -> cors.configurationSource(corsConfigurationSource()))  // CORS 설정 연결
                    // 세션 사용하지 않으므로 STATELESS로 설정
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안함 (Stateless 방식)

                    //== URL별 권한 관리 옵션 ==
                    .authorizeHttpRequests(authz -> authz
                            .requestMatchers("/oauth/**","/images/**", "/js/**", "/favicon.ico", "/h2-console/**", "/success").permitAll() // 공용 URL
                            .requestMatchers("/websocket/**").permitAll()
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()  // OPTIONS 요청은 모두 허용
                            .requestMatchers("/test").permitAll() // test
                            .requestMatchers("/getemail").authenticated()
                            .anyRequest().permitAll()
                    );

            http.oauth2Login(oauth2 -> oauth2
                    //하위 loginProcessingUrl에 리디렉션 url을 매핑시켜야함 -> 시큐리티에서 지정한 디폴트 경로를 쓰지 않을 시 사용
    //                .loginProcessingUrl("http:localhost:8080/api/v1/login")
    //                .loginPage("/login.html")
                    //오어스 로그인 성공 시 해당 정보를 기억한 채 추가 정보를 받아 회원가입할 예정
                    .successHandler(oAuth2LoginSuccessHandler)
                    .failureHandler(oAuth2LoginFailureHandler)
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(userService))  // CustomOAuth2UserService 등록

            );

            http.addFilterBefore(oAuth2JwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(jwtExceptionFilter, OAuth2JwtAuthFilter.class);

            return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.addAllowedOrigin("http://localhost:3000");  // 허용된 출처
            configuration.addAllowedOrigin("http://15.164.5.135");
            configuration.addAllowedOrigin("ws://localhost:5173"); // 웹소켓 허용
            configuration.addAllowedOrigin("ws://15.164.5.135");
            configuration.addAllowedMethod("*");  // 모든 HTTP 메소드 허용
            configuration.addAllowedHeader("*");  // 모든 헤더 허용
            configuration.setAllowCredentials(true);  // 자격 증명 허용
            configuration.addExposedHeader(HttpHeaders.AUTHORIZATION);

            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);  // 모든 경로에 대해 CORS 설정

            return source;
        }
        // 기본 제공되는 passwordEncoder가 아닌 사용자가 정의하는 encoder 방식을 등록하기 위해 빈을 재정의
        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

    }
