package study.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;
import study.security.constant.Role;

@Entity
@Getter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Data
public class Member {
	@Id
	@GeneratedValue
	private Long id;

	private String name;

	private String email;

	private String password;

	private String refreshToken;

	@Column(name = "user_role")
	@Enumerated(EnumType.STRING)
	private Role role;

	public void setRefreshToken(String token) {
		this.refreshToken = token;
	}
}
