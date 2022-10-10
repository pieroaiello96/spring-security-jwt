package it.pieroaiello.securityjwt.repository;

import it.pieroaiello.securityjwt.entities.AutenticationEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationRepository extends CrudRepository<AutenticationEntity, Long> {

    /**
     * Query for find user by username on 'access' table
     *
     * @param username
     * @return
     */
    @Query(value = "SELECT a FROM AutenticationEntity a WHERE a.username = :username")
    AutenticationEntity findByUsername(@Param("username") String username);
}
