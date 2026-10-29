package dev.kaidev.auth.hardening;

import java.time.Instant;
import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface DurableSessionRepository extends JpaRepository<DurableSession,UUID> {
    List<DurableSession> findByUserIdAndRevokedAtIsNullAndExpiresAtAfter(UUID userId, Instant now);
    @Modifying @Query("update DurableSession s set s.lastActivityAt=:now where s.id=:id and s.revokedAt is null and s.lastActivityAt<:before")
    void touch(@Param("id") UUID id,@Param("now") Instant now,@Param("before") Instant before);
    @Modifying @Query("update DurableSession s set s.revokedAt=:now where s.userId=:user and s.revokedAt is null")
    void revokeAll(@Param("user") UUID user,@Param("now") Instant now);
}
