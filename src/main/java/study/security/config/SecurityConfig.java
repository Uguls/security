package study.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;
import study.security.jwt.JwtAuthenticationFilter;
import study.security.jwt.JwtTokenProvider;

@Configuration // 스프링 설정 클래스로 등록
@EnableWebSecurity // Spring Security 설정 활성화
@RequiredArgsConstructor // final 필드를 생성자로 자동 주입 (Lombok)
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider; // JWT 토큰 생성 및 검증을 담당하는 클래스

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .cors(Customizer.withDefaults()) // CORS 설정: 기본 설정 적용
            .csrf(csrf -> csrf.disable()) // CSRF 보호 비활성화 (JWT는 세션이 없으므로 필요 없음)
            .formLogin(form -> form.disable()) // 폼 기반 로그인 비활성화 (프론트에서 로그인 처리)
            .httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 인증 비활성화 (Authorization 헤더 대신 JWT 사용)

            // URL별 접근 권한 설정
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/", "/login", "/signup").permitAll() // 인증 없이 접근 허용
                .requestMatchers("/admin/**").hasRole("ADMIN") // ADMIN 역할만 접근 가능
                .requestMatchers("/user/**").hasRole("USER") // USER 역할만 접근 가능
                .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
            )

            // 세션 설정: STATELESS → 세션을 생성하지 않고 JWT로 인증 처리
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // JWT 인증 필터를 UsernamePasswordAuthenticationFilter 전에 삽입
            .addFilterBefore(
                new JwtAuthenticationFilter(jwtTokenProvider),
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build(); // 최종 SecurityFilterChain 반환
    }

    // 비밀번호 암호화에 사용할 PasswordEncoder Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // 기본적으로 bcrypt 사용, 필요시 다른 알고리즘도 대응 가능
    }
}

