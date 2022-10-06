package it.pieroaiello.securityjwt.models.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticationModelResponse {
    private String jwttoken;

}

