# spring-security-jwt

### Usage:

On rest controller for authentication

```java

@RestController
public class AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    @PostMapping(value = "/auth")
    public ResponseEntity<?> createAuthenticationToken(AuthenticationModel user) throws UnauthorizedException {
        AuthenticationModel authenticationRequest = new AuthenticationModel(user.getUsername(), user.getPassword());
        return authenticationService.createAuthenticationToken(authenticationRequest);
    }
}

```

On controller to check grant permission add this annotation to method:

```java

@PreAuthorize("hasAnyAuthority('DIREZIONE') || hasAnyAuthority('HR')")

```
