package it.pieroaiello.securityjwt.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Component
public class JwtUtils {

    /**
     * Token validity in milliseconds
     */
    private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    /**
     * Secret value defined in application.properties for JWT signature
     */
    @Value("${jwt.secret}")
    private String secret;

    /**
     * Method for get the username from JWT token
     * The username is into subject field of JWT claims
     *
     * Ex. String username = getUsernameFromToken(token);
     *
     * @param token
     * @return
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Method for get the expiration date from JWT token
     * The username is into expiration field of JWT claims
     *
     * Ex. Date expirationDate = getUsernameFromToken(token);
     *
     * @param token
     * @return
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Private method to get specific claim from JWT token
     * This method is used in 'getUsernameFromToken' and 'getExpirationDateFromToken'
     *
     * @param token
     * @param claimsResolver
     * @param <T>
     * @return
     */
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Private method to get all claims from token
     *
     * @param token
     * @return
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    /**
     * Method to check is a token is expired
     *
     * @param token
     * @return
     */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * Method for add custom claims
     *
     * Ex. String token = generateToken(userDetails, user);
     *
     * @param userDetails
     * @param object
     * @return
     */
    public String generateToken(UserDetails userDetails, Object object) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("custom", object );
        return doGenerateToken(claims, userDetails.getUsername());
    }

    /**
     * Private method for generate JWT token
     *
     * @param claims
     * @param subject
     * @return
     */
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    /**
     * Method for tocket validation
     *
     * Ex. Boolean isValid = validateToken(token, userDetails);
     *
     * @param token
     * @param userDetails
     * @return
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
