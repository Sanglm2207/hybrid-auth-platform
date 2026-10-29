package dev.kaidev.auth.identity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "identity_devices", uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "device_id"}))
public class AuthDevice {
    @Id public UUID id = UUID.randomUUID();
    @Column(nullable = false) public UUID userId;
    @Column(nullable = false) public UUID deviceId;
    @Column(nullable = false, length = 256) public String userAgent;
    @Column(nullable = false, length = 64) public String lastIp;
    @Column(nullable = false) public Instant firstSeenAt;
    @Column(nullable = false) public Instant lastSeenAt;
    @Override public String toString() { return "AuthDevice[REDACTED]"; }
}
