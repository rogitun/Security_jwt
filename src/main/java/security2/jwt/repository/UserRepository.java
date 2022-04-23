package security2.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security2.jwt.model.User;

public interface UserRepository extends JpaRepository<User,Long> {

    User findByUsername(String username);
}
