package dev.kaidev.user.repository;

import dev.kaidev.user.entity.UserProfile;
import jakarta.persistence.LockModeType;
import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface ProfileRepository extends JpaRepository<UserProfile, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from UserProfile p where p.userId = :id")
    Optional<UserProfile> findForUpdate(@Param("id") UUID id);
}
