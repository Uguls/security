package study.security.jwt;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import study.security.entity.Member;
import study.security.repository.MemberRepository;

@Service // 해당 클래스를 Spring의 서비스 빈으로 등록
@RequiredArgsConstructor // final 필드를 생성자로 주입 (Lombok)
public class CustomUserDetailsService implements UserDetailsService {

	// DB에서 사용자 정보를 조회하기 위한 JPA Repository 의존성 주입
	private final MemberRepository memberRepository;

	// 인증 시 username을 기반으로 유저 정보를 로드하는 메서드 (Spring Security 필수 구현)
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

		// username으로 DB에서 사용자 조회, 없으면 예외 발생
		Member member = memberRepository.findByEmail(email)
			.orElseThrow(() -> new UsernameNotFoundException("Member not found"));

		// 사용자 권한 정보를 Spring Security의 형식으로 변환
		List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(member.getRole().name()));

		// 사용자 정보를 담은 CustomUserDetails 객체 생성 및 반환
		return new CustomUserDetails(
			member.getId(),           // 사용자 PK (userId)
			member.getName(),         // 사용자 이름 (username)
			member.getPassword(),     // 암호화된 비밀번호
			authorities             // 권한 목록
		);

	}
}
