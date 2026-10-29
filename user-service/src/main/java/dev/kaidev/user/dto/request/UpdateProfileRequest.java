package dev.kaidev.user.dto.request;

import jakarta.validation.constraints.*;

public record UpdateProfileRequest(@Size(max = 100) String displayName, @Size(max = 500) String bio,
        @Size(max = 35) @Pattern(regexp = "[a-zA-Z]{2,8}(-[a-zA-Z0-9]{1,8})*") String locale,
        @Size(min = 1, max = 64) String timeZone, @PositiveOrZero Long version) {
    @Override public String toString() { return "UpdateProfileRequest[REDACTED]"; }
}
