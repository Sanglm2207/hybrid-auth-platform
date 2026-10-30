package dev.kaidev.auth.repository;

import dev.kaidev.auth.entity.AppUser;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.*;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByEmail(String email);
    @Query("select u from AppUser u where u.deletedAt is null and (locate(:q,lower(u.email))>0 or :q='') and (:locked is null or u.adminLocked=:locked) and (:active is null or u.active=:active)")
    List<AppUser> search(@Param("q")String q,@Param("locked")Boolean locked,@Param("active")Boolean active,org.springframework.data.domain.Pageable page);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where u.id = :id")
    Optional<AppUser> findByIdForUpdate(@Param("id") UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from AppUser u where u.email = :email")
    Optional<AppUser> findByEmailForUpdate(@Param("email") String email);
}
