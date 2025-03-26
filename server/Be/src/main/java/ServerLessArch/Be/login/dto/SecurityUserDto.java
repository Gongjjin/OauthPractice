package ServerLessArch.Be.login.dto;

import lombok.Builder;
import lombok.Data;
@Builder
@Data
public class SecurityUserDto {
    private Long memberNo;
    private String email;
    private String role;
}
