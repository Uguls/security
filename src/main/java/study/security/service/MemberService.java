package study.security.service;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import study.security.constant.Role;
import study.security.dto.TokenInfo;
import study.security.dto.request.MemberSignInRequestDto;
import study.security.entity.Member;
import study.security.jwt.JwtTokenProvider;
import study.security.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    /**
     * 사용자의 ID(PK)와 비밀번호로 JWT 토큰을 생성하는 메서드
     * @param password - 사용자 비밀번호
     * @return TokenInfo - 발급된 AccessToken과 RefreshToken
     * @throws Exception
     */
    @Transactional
    public TokenInfo getToken(String email, String password){

        // 1. 사용자의 로그인 요청 정보로 Authentication 객체를 생성 (아직 인증은 되지 않은 상태)
        // principal: memberId, credentials: password
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
            email, password);

        // 2. 실제 인증 절차 수행
        // 내부적으로 UserDetailsService.loadUserByUsername() 호출됨
        // 반환된 UserDetails와 입력된 비밀번호 비교 후 인증
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증에 성공하면 JWT 토큰 발급
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

		// 4. 발급한 RefreshToken을 DB에 저장 (사용자 정보에 포함)
        Member member = memberRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("유저 조회 실패"));
        member.setRefreshToken(tokenInfo.getRefreshToken());

        return tokenInfo;
    }

	public Member saveUser(MemberSignInRequestDto dto) {
        String encodedPassword = passwordEncoder.encode(dto.getPassword());
		Member member = Member.builder()
			.email(dto.getEmail())
			.name(dto.getName())
			.password(encodedPassword)
			.role(Role.ROLE_USER)
			.build();

		memberRepository.save(member);

		return member;

	}

}
