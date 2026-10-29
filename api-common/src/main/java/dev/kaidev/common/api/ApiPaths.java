package dev.kaidev.common.api;

/** Versioned API roots shared by controllers and security configuration. */
public final class ApiPaths {
    public static final String V1 = "/api/v1";
    public static final String AUTH_V1 = V1 + "/auth";
    public static final String USERS_V1 = V1 + "/users";

    private ApiPaths() {}
}
