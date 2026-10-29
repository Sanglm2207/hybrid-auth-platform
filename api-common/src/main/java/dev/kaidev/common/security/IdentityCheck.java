package dev.kaidev.common.security;

import jakarta.validation.constraints.*;
import java.util.*;

/** Internal state check performed only after cryptographic JWT verification by the caller. */
public record IdentityCheck(@NotNull UUID subject, @NotNull UUID sessionId,
        @NotNull @PositiveOrZero Long sessionVersion, @NotNull @PositiveOrZero Long credentialRevision) {
    public static IdentityCheck fromClaims(Map<String, Object> claims) {
        return new IdentityCheck(UUID.fromString((String) claims.get("sub")), UUID.fromString((String) claims.get("sid")),
                integer(claims.get("sv")), integer(claims.get("cv")));
    }
    private static Long integer(Object value) {
        if (!(value instanceof Number n) || n.longValue() < 0 || n.doubleValue() != n.longValue())
            throw new IllegalArgumentException("Missing identity version claims");
        return n.longValue();
    }
    @Override public String toString() { return "IdentityCheck[REDACTED]"; }
}
