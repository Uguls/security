package study.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import study.security.entity.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {
	Optional<Member> findByEmail(String email);
}
