package tn.esprit.springboot_jwt_authentication_authorisation.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.esprit.springboot_jwt_authentication_authorisation.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email);
}
