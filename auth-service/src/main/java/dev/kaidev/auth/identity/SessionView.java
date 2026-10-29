package dev.kaidev.auth.identity;

import java.time.Instant;
import java.util.UUID;

public record SessionView(UUID id, UUID deviceId, String userAgent, String ip, Instant createdAt,
        Instant lastActivityAt, Instant expiresAt, boolean current) {
    @Override public String toString() { return "SessionView[REDACTED]"; }
}
