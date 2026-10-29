package dev.kaidev.user.dto.response;

import java.time.Instant;
import java.util.List;

public record ProfileResponse(String id, List<String> roles, String displayName, String bio, String locale,
        String timeZone, Instant updatedAt, long version) {
    @Override public String toString() { return "ProfileResponse[REDACTED]"; }
}
