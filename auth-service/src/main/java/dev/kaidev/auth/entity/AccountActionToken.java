package dev.kaidev.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "account_action_tokens")
public class AccountActionToken {
    public enum Purpose { RESET_PASSWORD, CHANGE_EMAIL }
    @Id public UUID id = UUID.randomUUID();
    @Column(nullable = false) public UUID userId;
    @Column(nullable = false, unique = true, length = 64) public String tokenHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) public Purpose purpose;
    @Column(nullable = false) public long credentialRevision;
    @Column(length = 254) public String targetEmail;
    @Column(nullable = false) public Instant createdAt;
    @Column(nullable = false) public Instant expiresAt;
    public Instant consumedAt;
    @Override public String toString() { return "AccountActionToken[REDACTED]"; }
}
