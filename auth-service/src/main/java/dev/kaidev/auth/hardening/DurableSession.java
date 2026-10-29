package dev.kaidev.auth.hardening;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name="identity_sessions")
public class DurableSession {
    @Id public UUID id;
    @Column(nullable=false) public UUID userId;
    @Column(nullable=false) public long generation;
    @Column(nullable=false) public long credentialRevision;
    @Column(nullable=false,length=64) public String currentHash;
    @Column(nullable=false) public UUID deviceId;
    @Column(nullable=false,length=256) public String userAgent;
    @Column(nullable=false,length=64) public String ip;
    @Column(nullable=false) public Instant createdAt;
    @Column(nullable=false) public Instant lastActivityAt;
    @Column(nullable=false) public Instant expiresAt;
    public Instant revokedAt;
    @Override public String toString(){return "DurableSession[REDACTED]";}
}
