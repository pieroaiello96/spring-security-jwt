package it.pieroaiello.securityjwt.config;


import it.pieroaiello.securityjwt.component.JwtAuthenticationEntryPoint;
import it.pieroaiello.securityjwt.component.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    /**
     * Autowired for security user services
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * Autowired methods for JWT authentication entry poiny
     */
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /**
     * Autowired methods for JWT reqeust filter
     */
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    /**
     * Autowired method for global configuration
     *
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * Method for password encoder
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Method to get authentication manager bean
     *
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Method for configure http security
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeHttpRequests((auth) ->
                {
                    try {
                        auth.antMatchers("/auth", "/login", "/authentication","/token").permitAll()
                            .anyRequest().authenticated()
                                .and().exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
        ).httpBasic(withDefaults());

        http.cors();
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
