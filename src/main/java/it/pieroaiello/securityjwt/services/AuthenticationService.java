package it.pieroaiello.securityjwt.services;

import it.pieroaiello.securityjwt.component.JwtUtils;
import it.pieroaiello.securityjwt.entities.UserEntity;
import it.pieroaiello.securityjwt.exception.UnauthorizedException;
import it.pieroaiello.securityjwt.models.AuthenticationModel;
import it.pieroaiello.securityjwt.models.response.AuthenticationModelResponse;
import it.pieroaiello.securityjwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityUserDetailsService securityUserDetailsService;

    public ResponseEntity<?> createAuthenticationToken(AuthenticationModel authenticationRequest) throws UnauthorizedException {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
        try {
            UserDetails userDetails = securityUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
            UserEntity user = userRepository.findByUsername(userDetails.getUsername());
            String token = jwtUtils.generateToken(userDetails, user);
            log.info("User {} is authenticated", user.getUsername());
            return ResponseEntity.ok(new AuthenticationModelResponse(token));
        }  catch (Exception ex) {
            log.error(ex.getMessage());
            throw new UnauthorizedException(ex.getMessage());
        }
    }


    private void authenticate(String username, String password) throws  UnauthorizedException {
        log.debug("Start Autentication");
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new UnauthorizedException("USER_DISABLED: "+e.getMessage());
        } catch (BadCredentialsException e) {
            throw new UnauthorizedException("INVALID_CREDENTIALS: "+e.getMessage());
        }
        log.debug("End Authentication");
    }

}
