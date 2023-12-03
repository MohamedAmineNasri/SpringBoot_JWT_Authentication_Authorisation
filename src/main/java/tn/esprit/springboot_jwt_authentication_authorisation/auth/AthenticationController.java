package tn.esprit.springboot_jwt_authentication_authorisation.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
//    public ResponseEntity<AuthenticationResponse> register(
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request //RegisterRequest will all the registration information
    ) {
//        return ResponseEntity.ok(service.register(request));
        var response = service.register(request);
        if (request.isMfaEnabled()) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request //RegisterRequest will all the registration information
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,//the object where we can get or read the authorization header which will hold the refresh token
            HttpServletResponse response//the object that will help us to re-inject or to send back the response
    ) throws IOException {
        service.refreshToken(request,response);
    }
}
