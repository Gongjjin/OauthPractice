package ServerLessArch.Be.user.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.lang.Nullable;
import org.springframework.validation.annotation.Validated;
import java.util.HashSet;
import java.util.Set;

@Getter @Setter
@Entity
@Validated
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Email(message = "잘못된 형식입니다")
    @Column(nullable = true)
    private String email;
    private String password;
    @Column(nullable = true)
    private String name;
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "roles", joinColumns = @JoinColumn(name = "user_id"))
    private Set<Roles> roles = new HashSet<>();
    private String provider;
    private String providerId;
    private String phone;
    private String role;

    public static User createUser(String name, String email, String phone, String role){
        User user = new User();
        user.name = name;
        user.email = email;
        user.phone = phone;
        user.role = role;
        return user;
    }

    public void addUserRoles(Roles roles){
        if(this.roles.contains(roles)){
            return;
        }
        else this.roles.add(roles);
    }

    public void removeRoles(Roles roles){
        if(this.roles.contains(roles)){
            this.roles.remove(roles);
        }
        else return;
    }
}
