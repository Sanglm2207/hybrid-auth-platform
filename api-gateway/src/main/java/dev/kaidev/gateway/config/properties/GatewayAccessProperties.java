package dev.kaidev.gateway.config.properties;

import jakarta.validation.constraints.NotEmpty;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("app.gateway")
public record GatewayAccessProperties(@NotEmpty List<String> allowedHosts,
        @NotEmpty List<String> allowedOrigins, boolean requireOrigin) {
    public GatewayAccessProperties {
        if (allowedHosts != null) {
            allowedHosts = allowedHosts.stream().map(String::strip).map(host -> host.toLowerCase(Locale.ROOT)).toList();
            for (String host : allowedHosts) {
                if (!host.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\\[::1\\]"))
                    throw new IllegalArgumentException("Allowed hosts must be exact hostnames without scheme, wildcard or port");
            }
        }
        if (allowedOrigins != null) {
            allowedOrigins = allowedOrigins.stream().map(String::strip).toList();
            for (String origin : allowedOrigins) {
                URI uri = URI.create(origin);
                if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
                        || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                        || uri.getRawFragment() != null || !uri.getRawPath().isEmpty())
                    throw new IllegalArgumentException("Allowed origins must be exact http(s) origins without paths or wildcards");
            }
        }
    }
}
