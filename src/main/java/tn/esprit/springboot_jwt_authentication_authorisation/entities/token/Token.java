package tn.esprit.springboot_jwt_authentication_authorisation.entities.token;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import tn.esprit.springboot_jwt_authentication_authorisation.entities.User;

import java.io.Serializable;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Token implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;


    private boolean expired;
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name ="user_id")
    private User user;
}
