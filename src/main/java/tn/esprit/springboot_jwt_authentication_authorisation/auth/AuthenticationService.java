package tn.esprit.springboot_jwt_authentication_authorisation.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tn.esprit.springboot_jwt_authentication_authorisation.config.JwtService;
import tn.esprit.springboot_jwt_authentication_authorisation.entities.Role;
import tn.esprit.springboot_jwt_authentication_authorisation.entities.User;
import tn.esprit.springboot_jwt_authentication_authorisation.repositories.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    public AuthenticationResponse register(RegisterRequest request) {
        //this method will allow us to create a user and save it in the database and return the
        //generated token out of it
        var user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        return null;
    }
}
