package dev.kaidev.auth.entity;

import jakarta.persistence.*;
import java.util.UUID;
import java.time.Instant;

@Entity
@Table(name = "app_users")
public class AppUser {
    @Id
    public UUID id = UUID.randomUUID();
    @Column(nullable = false, unique = true)
    public String email;
    @Column(nullable = false)
    public String passwordHash;
    @Column(name = "role", nullable = false)
    private String legacyRole = "USER";
    @ElementCollection
    @CollectionTable(name = "identity_user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role_name", nullable = false, length = 32)
    public java.util.Set<String> roles = new java.util.HashSet<>(java.util.Set.of("USER"));
    @Column(nullable = false)
    public boolean active = true;
    public Instant deactivatedAt;

    @Column(nullable = false)
    public boolean emailVerified;
    @Column(nullable = false)
    public long credentialRevision;
    @Column(nullable = false) public long sessionGeneration;
    public Instant passwordResetResendAt;
    public Instant emailChangeResendAt;
    public String emailOtpHash;
    public Instant emailOtpExpiresAt;
    public Instant emailOtpResendAt;
    @Column(nullable = false)
    public int emailOtpAttempts;

    protected AppUser() {
    }

    public AppUser(String email, String hash) {
        this.email = email;
        this.passwordHash = hash;
    }
}
