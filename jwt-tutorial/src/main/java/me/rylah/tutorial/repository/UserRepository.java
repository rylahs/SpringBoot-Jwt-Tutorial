package me.rylah.tutorial.repository;

import me.rylah.tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities") // 해당 쿼리가 수행 될 때 fetch join(EAGER)로 정보를 가져옴
    Optional<User> findOneWithAuthoritiesByUsername(String username); // 권한정보도 같이 가져오는 메소드

}
