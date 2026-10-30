package dev.kaidev.auth.repository;

import dev.kaidev.auth.entity.AccountActionToken;
import dev.kaidev.auth.entity.AccountActionToken.Purpose;
import java.time.Instant;
import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface AccountActionTokenRepository extends JpaRepository<AccountActionToken, UUID> {
    @Modifying @Query("delete from AccountActionToken t where t.userId=:user")
    void eraseFor(@Param("user")UUID user);
    Optional<AccountActionToken> findByTokenHash(String hash);

    @Query("select t.userId from AccountActionToken t where t.tokenHash = :hash")
    Optional<UUID> findUserIdByTokenHash(@Param("hash") String hash);

    @Modifying
    @Query("update AccountActionToken t set t.consumedAt = :now where t.userId = :userId and t.purpose = :purpose and t.consumedAt is null")
    void invalidate(@Param("userId") UUID userId, @Param("purpose") Purpose purpose, @Param("now") Instant now);

    @Modifying
    @Query("update AccountActionToken t set t.consumedAt = :now where t.userId = :userId and t.consumedAt is null")
    void invalidateAll(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("delete from AccountActionToken t where t.expiresAt < :before")
    void deleteExpired(@Param("before") Instant before);
}
