package study.security.dto.request;

import lombok.Data;

@Data
public class MemberSignInRequestDto {

	private String name;
	private String email;
	private String password;

}
