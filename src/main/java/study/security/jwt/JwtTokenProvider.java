package study.security.jwt;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import study.security.dto.TokenInfo;

@Slf4j // 로그를 위한 Lombok 어노테이션
@Component // Spring Bean으로 등록
public class JwtTokenProvider {

    private final Key key; // JWT 서명용 비밀 키

    // 생성자 주입: application.properties의 jwt.secret 값을 가져와 Key 객체 생성
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        String base64Encoded = Base64.getEncoder().encodeToString(secretKey.getBytes());
        byte[] bytes = Decoders.BASE64.decode(secretKey); // BASE64로 인코딩된 비밀 키를 디코딩
        this.key = Keys.hmacShaKeyFor(bytes); // 서명용 HMAC-SHA Key 생성
    }

    // JWT 토큰(Access/Refresh)을 생성하는 메서드
    public TokenInfo generateToken(Authentication authentication) {

        // 현재 인증된 사용자의 권한 목록을 ","로 연결된 문자열로 변환
        String authorities = authentication.getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

        long now = (new Date()).getTime(); // 현재 시각 (밀리초)
        Date accessTokenExpiresIn = new Date(now + 1800000); // Access Token 유효 시간: 30분

        // 인증 객체에서 CustomUserDetails를 꺼내고 userId 추출
        CustomUserDetails userDetails = (CustomUserDetails)authentication.getPrincipal();
        Long userId = userDetails.getUserId();

        // Access Token 생성: subject(username), auth(권한), user_id, 만료일자 포함
        String accessToken = Jwts.builder()
            .setSubject(authentication.getName()) // username
            .claim("auth", authorities) // 권한 정보
            .claim("user_id", userId) // 사용자 고유 ID (PK)
            .setExpiration(accessTokenExpiresIn) // 만료 시간 설정
            .signWith(key, SignatureAlgorithm.HS256) // 비밀 키로 서명
            .compact(); // 토큰 생성 완료

        // Refresh Token 생성: user_id만 포함하고 유효기간은 1일
        String refreshToken = Jwts.builder()
            .claim("user_id", userId) // 사용자 고유 ID
            .setExpiration(new Date(now + 86400000)) // 만료 시간: 24시간
            .signWith(key, SignatureAlgorithm.HS256) // 서명
            .compact();

        // Access/Refresh Token을 포함한 TokenInfo DTO 리턴
        return TokenInfo.builder()
            .grantType("Bearer")
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
    }

    // Access Token으로부터 인증 정보를 복원하는 메서드
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken); // 토큰 복호화 → Claims 추출

        if (claims.get("auth") == null) { // 권한 정보 없으면 예외 발생
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // "auth" 문자열을 파싱해서 권한 리스트로 변환
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(
                claims.get("auth").toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        // user_id 추출 (JWT는 숫자를 Number로 반환하므로 캐스팅 필요)
        Long userId = ((Number)claims.get("user_id")).longValue();

        // CustomUserDetails 객체 생성 (비밀번호는 빈 문자열, 실제 사용 안 함)
        CustomUserDetails principal = new CustomUserDetails(
            userId,
            claims.getSubject(), // username
            "",
            authorities
        );

        // UsernamePasswordAuthenticationToken을 통해 Authentication 객체 생성 후 리턴
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // Refresh Token에서 user_id만 추출하는 메서드
    public Long getUserIdByRefreshToken(String refreshToken) {
        Claims claims = parseClaims(refreshToken); // 토큰 복호화
        return ((Number)claims.get("user_id")).longValue(); // user_id 추출
    }

    // JWT 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); // 파싱 성공 = 유효함
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e); // 서명 오류, 형식 오류
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e); // 만료된 토큰
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e); // 지원하지 않는 형식
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e); // claim이 없음
        }
        return false; // 예외 발생 → 무효한 토큰
    }

    // JWT를 파싱해서 Claims 객체로 반환하는 내부 유틸 메서드
    private Claims parseClaims(String accessToken) {
        try {
            // 만료되지 않은 경우는 정상적으로 Claims 리턴
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            // 만료된 경우에도 Claims는 꺼낼 수 있으므로 예외에서 추출
            return e.getClaims();
        }
    }
}
