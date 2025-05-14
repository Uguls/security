package study.security.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import study.security.dto.request.MemberLoginRequestDto;
import study.security.dto.TokenInfo;
import study.security.dto.request.MemberSignInRequestDto;
import study.security.entity.Member;
import study.security.service.MemberService;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

	private final MemberService memberService;

	@PostMapping("/signin")
	public ResponseEntity<String> siginIn(@RequestBody MemberSignInRequestDto dto) {
		Member saved = memberService.saveUser(dto);
		return ResponseEntity.status(HttpStatus.CREATED).body(saved.toString());
	}

	@PostMapping("/login")
	public ResponseEntity<TokenInfo> login(@RequestBody MemberLoginRequestDto dto,
		HttpServletResponse response) {
			TokenInfo tokenInfo = memberService.getToken(dto.getEmail(), dto.getPassword());
			return ResponseEntity.ok(tokenInfo);
	}

}
