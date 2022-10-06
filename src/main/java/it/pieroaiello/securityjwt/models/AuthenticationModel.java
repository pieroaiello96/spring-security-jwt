package it.pieroaiello.securityjwt.models;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationModel {

    private String username;

    @ToString.Exclude
    private String password;
}
