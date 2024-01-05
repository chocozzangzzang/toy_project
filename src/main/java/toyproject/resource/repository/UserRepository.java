package toyproject.resource.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import toyproject.resource.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUsername(String username);

    // DB에서 USER 정보를 받아옴
    UserEntity findByUsername(String username);


}
