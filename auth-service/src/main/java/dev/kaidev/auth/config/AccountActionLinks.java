package dev.kaidev.auth.config;

import dev.kaidev.common.api.ApiPaths;
import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Fixed public origin; never derive recovery links from request/forwarded headers. */
@Component
public class AccountActionLinks {
    private final String origin;

    public AccountActionLinks(@Value("${app.account.public-base-url:http://localhost:8700}") String value) {
        URI uri = URI.create(value);
        boolean local = java.util.Set.of("localhost", "127.0.0.1", "[::1]").contains(
                uri.getHost() == null ? "" : uri.getHost());
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))
                || !("https".equals(uri.getScheme()) || (local && "http".equals(uri.getScheme()))))
            throw new IllegalArgumentException("Account public base URL must be an HTTPS origin (HTTP allowed for loopback only)");
        origin = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public String reset(String token) { return link("reset-password", token); }
    public String confirmEmail(String token) { return link("confirm-email-change", token); }
    private String link(String path, String token) {
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException("Invalid account proof");
        // Fragments never reach HTTP access logs or Referer headers.
        return origin + ApiPaths.AUTH_V1 + "/" + path + "#token=" + token;
    }
}
