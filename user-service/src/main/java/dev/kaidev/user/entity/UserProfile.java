package dev.kaidev.user.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_profiles")
public class UserProfile {
    @Id public UUID userId;
    @Column(nullable = false, length = 100) public String displayName = "";
    @Column(nullable = false, length = 500) public String bio = "";
    @Column(nullable = false, length = 35) public String locale = "en";
    @Column(nullable = false, length = 64) public String timeZone = "UTC";
    @Column(nullable = false) public Instant updatedAt = Instant.now();
    @Version @Column(nullable = false) public Long version;
    protected UserProfile() {}
    public UserProfile(UUID userId) { this.userId = userId; }
    @Override public String toString() { return "UserProfile[REDACTED]"; }
}
