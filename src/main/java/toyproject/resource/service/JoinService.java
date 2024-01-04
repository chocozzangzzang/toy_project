package toyproject.resource.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import toyproject.resource.dto.JoinDTO;
import toyproject.resource.entity.UserEntity;
import toyproject.resource.repository.UserRepository;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isUserValid = userRepository.existsByUsername(username);

        if (isUserValid) {

            return;
        }

        UserEntity user = new UserEntity();

        user.setUsername(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setRole("ROLE_ADMIN");

        userRepository.save(user);
    }

}
