package dev.kaidev.auth.identity;

import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceRepository extends JpaRepository<AuthDevice, UUID> {
    Optional<AuthDevice> findByUserIdAndDeviceId(UUID userId, UUID deviceId);
    List<AuthDevice> findByUserIdOrderByLastSeenAtDesc(UUID userId);
}
