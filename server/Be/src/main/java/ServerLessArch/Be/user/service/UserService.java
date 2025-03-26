package ServerLessArch.Be.user.service;

import ServerLessArch.Be.login.dto.LoginDTO;
import ServerLessArch.Be.user.domain.User;
import ServerLessArch.Be.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    public void joinUser(LoginDTO loginDTO){
        User user = User.createUser(loginDTO.getName(), loginDTO.getEmail(), loginDTO.getPhone(), loginDTO.getRole());
        userRepository.save(user);
    }
}
