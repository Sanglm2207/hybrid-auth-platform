package dev.kaidev.auth.hardening;

import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface DurableRefreshRepository extends JpaRepository<DurableRefresh,String> {
    @Query("select r.userId from DurableRefresh r where r.tokenHash=:hash") Optional<UUID> owner(@Param("hash") String hash);
}
