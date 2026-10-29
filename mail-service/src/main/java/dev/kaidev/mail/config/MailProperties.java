package dev.kaidev.mail.config;

import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("app.mail")
public record MailProperties(String apiKey, String from, Map<String, Template> templates,
        @DefaultValue("Hybrid Auth Security Team") String signature) {
    @ConstructorBinding
    public MailProperties {
        if (signature == null || signature.isBlank() || signature.length() > 160
                || signature.contains("\r") || signature.contains("\n"))
            throw new IllegalArgumentException("Mail signature must be a nonblank single line, up to 160 characters");
    }
    public MailProperties(String apiKey, String from, Map<String, Template> templates) {
        this(apiKey, from, templates, "Hybrid Auth Security Team");
    }
    public record Template(String subject, String html, String text) {}
    @Override public String toString() { return "MailProperties[REDACTED]"; }
}
