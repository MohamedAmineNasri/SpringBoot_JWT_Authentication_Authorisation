package tn.esprit.springboot_jwt_authentication_authorisation.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tn.esprit.springboot_jwt_authentication_authorisation.entities.token.Token;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer> {

    @Query("""
        select t from Token t inner join User u on t.user.id = u.id 
        where u.id = :userId  and (t.expired = false or t.revoked = false)
""")
    List<Token> findAllValidTokensByUser(Integer userId);

    Optional<Token> findByToken(String token);
}
