package tn.esprit.springboot_jwt_authentication_authorisation.auth;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VerficationRequest {
    private String email;
    private String code;
}
