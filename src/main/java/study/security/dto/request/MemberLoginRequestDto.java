package study.security.dto.request;

import lombok.Data;

@Data
public class MemberLoginRequestDto {
	private String email;
	private String password;
}
