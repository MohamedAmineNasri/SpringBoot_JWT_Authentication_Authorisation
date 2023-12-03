package tn.esprit.springboot_jwt_authentication_authorisation.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
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
    //JwtService check if the token expired of the user exist or not

    //private static final String SECRET_KEY = "ZiWNkc8o7xndwmjQBr+Wyz8UCkwyi+dRj7ehppNLmb37Z/PVLLnQn5rzfd6vgUrj";
    @Value("${jwt.secret-key}")
    private String SECRETKEY;
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    @Value("${jwt.refresh.expiration}")
    private long refreshExpiration;
    //from this website :
    // https://generate-random.org/encryption-key-generator?count=1&bytes=32&cipher=aes-256-cbc&string=&password=


    private KeyPair keyPair;

    public JwtService() {
        // Initialize the key pair during the service instantiation
        this.keyPair = generateKeyPair();
    }

    private KeyPair generateKeyPair() {
        // Generate an ECDSA key pair
        return Keys.keyPairFor(SignatureAlgorithm.ES256);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken( UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration)
    {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.ES256)
                .compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(keyPair.getPublic()).build().parseClaimsJws(token).getBody();
    }
}
