package tn.esprit.springboot_jwt_authentication_authorisation.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.KeyPair;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "ZiWNkc8o7xndwmjQBr+Wyz8UCkwyi+dRj7ehppNLmb37Z/PVLLnQn5rzfd6vgUrj";
    //from this website :
    // https://generate-random.org/encryption-key-generator?count=1&bytes=32&cipher=aes-256-cbc&string=&password=


    // This method specifically extracts the username claim from a JWT token.
    // It utilizes the more general extractClaim method by providing a claimResolver function.
    public String extractUsername(String token) {
        // Uses the extractClaim method to extract the subject claim (username) from the provided JWT token.
        // Claims::getSubject is a method reference, representing the getSubject method of the Claims class.
        // This method is used to retrieve the subject (username) from the claims.
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    public String generateToken(
            Map<String, Object> extraClaims,//Extra claims to include in the JWT payload.
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.ES256)
                .compact();

    }


    // This method extracts a specific claim from a JWT token.
    // It takes a token and a function (claimResolver) as parameters.
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        // Extracts all claims from the provided JWT token.
        final Claims claims = extractAllClaims(token);

        // Applies the claimResolver function to the extracted claims.
        // The claimResolver function is responsible for extracting a specific claim of type T.
        return claimResolver.apply(claims);
    }


    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private Key getSigningKey() {
        // Generate an ECDSA key pair
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);

        // Use the private key for signing
        return keyPair.getPrivate();
    }

}