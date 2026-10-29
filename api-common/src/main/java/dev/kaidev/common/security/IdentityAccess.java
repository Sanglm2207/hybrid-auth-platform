package dev.kaidev.common.security;

import java.util.*;
import java.util.stream.Stream;

public record IdentityAccess(boolean active, Set<String> roles, Set<String> permissions) {
    public static IdentityAccess denied() { return new IdentityAccess(false, Set.of(), Set.of()); }
    public List<String> authorities() {
        if (!active || roles == null || permissions == null) return List.of();
        return Stream.concat(roles.stream().map(role -> "ROLE_" + role), permissions.stream()).distinct().toList();
    }
}
