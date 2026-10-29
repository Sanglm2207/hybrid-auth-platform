package dev.kaidev.auth.identity;

import java.util.Set;

public final class Permissions {
    public static final Set<String> ALL = Set.of("profile:read", "profile:write", "sessions:read", "sessions:revoke",
            "devices:read", "devices:revoke", "account:deactivate", "roles:manage");
    private Permissions() {}
}
