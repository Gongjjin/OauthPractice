package ServerLessArch.Be.login.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @NoArgsConstructor @AllArgsConstructor
public class LoginDTO {
    private String email;
    private String name;
    private String phone;
    private String role;
}
