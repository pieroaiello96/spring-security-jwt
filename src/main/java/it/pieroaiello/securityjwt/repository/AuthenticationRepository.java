package it.pieroaiello.securityjwt.repository;

import it.pieroaiello.securityjwt.entities.AutenticationEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationRepository extends CrudRepository<AutenticationEntity, Long> {

    @Query(value = "SELECT a FROM AutenticationEntity a WHERE a.username = :username")
    AutenticationEntity findByUsername(@Param("username") String username);
}
