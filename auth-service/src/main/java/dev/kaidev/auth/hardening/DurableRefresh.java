package dev.kaidev.auth.hardening;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name="identity_refresh_ledger")
public class DurableRefresh {
    @Id @Column(length=64) public String tokenHash;
    @Column(nullable=false) public UUID userId;
    @Column(nullable=false) public UUID sessionId;
    @Column(nullable=false) public Instant expiresAt;
    public Instant consumedAt;
    @Override public String toString(){return "DurableRefresh[REDACTED]";}
}
