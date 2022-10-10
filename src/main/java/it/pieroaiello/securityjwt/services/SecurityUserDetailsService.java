package it.pieroaiello.securityjwt.services;

import it.pieroaiello.securityjwt.entities.AutenticationEntity;
import it.pieroaiello.securityjwt.entities.UserEntity;
import it.pieroaiello.securityjwt.repository.AuthenticationRepository;
import it.pieroaiello.securityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class SecurityUserDetailsService implements UserDetailsService {

    /**
     * Autowired authentication repository for authentication with database
     */
    @Autowired
    private AuthenticationRepository authenticationRepository;

    /**
     * Autowired user repostiory for query operation with user
     */
    @Autowired
    private UserRepository userRepository;

    /**
     * Override method to load a user by username
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try{
            AutenticationEntity authUser = authenticationRepository.findByUsername(username);
            return new User(authUser.getUsername(), authUser.getPassword(), getAuthorities(username));
        }catch (Exception ex){
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }

    /**
     * Private method for get all granted authorities
     *
     * @param username
     * @return
     */
    private Collection<? extends GrantedAuthority> getAuthorities(String username) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        UserEntity user = userRepository.findByUsername(username);
        authorities.add(new SimpleGrantedAuthority(checkGrant(user.getIdRuolo())));
        return authorities;
    }

    /**
     * Get grant by User role
     *
     * @param role
     * @return
     */
    private String checkGrant(Integer role){
        switch (role){
            case 0:
                return "SIMPLE_GRANT";
            case 1:
                return "ADMIN";
            default:
                return "SIMPLE_GRANT";
        }
    }
}
