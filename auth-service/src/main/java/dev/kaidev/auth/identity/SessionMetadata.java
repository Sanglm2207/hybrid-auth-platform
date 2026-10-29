package dev.kaidev.auth.identity;

import java.util.UUID;

public record SessionMetadata(String userId, long generation, long credentialRevision, UUID deviceId, String userAgent, String ip,
        long createdAt, long lastActivity, long expiresAt) {
    @Override public String toString() { return "SessionMetadata[REDACTED]"; }
}
