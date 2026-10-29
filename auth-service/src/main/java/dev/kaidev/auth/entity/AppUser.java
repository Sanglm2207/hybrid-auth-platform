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
    @Column(nullable = false)
    public String role = "USER";

    @Column(nullable = false)
    public boolean emailVerified;
    @Column(nullable = false)
    public long credentialRevision;
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
