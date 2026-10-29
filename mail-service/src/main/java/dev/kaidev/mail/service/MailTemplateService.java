package dev.kaidev.mail.service;

import dev.kaidev.common.exception.ApiException;
import dev.kaidev.mail.config.MailProperties;
import dev.kaidev.mail.constant.MailCode;
import dev.kaidev.mail.dto.RenderedMail;
import dev.kaidev.mail.dto.TemplateResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

/** Trusted templates are loaded once at startup; callers supply plain text values only. */
@Service
public class MailTemplateService {
    private static final Pattern VARIABLE = Pattern.compile("\\{\\{([a-zA-Z][a-zA-Z0-9_]{0,63})\\}\\}");
    private record Template(String subject, String html, String text, Set<String> variables) {}
    private final Map<String, Template> templates;
    private final String signature;

    public MailTemplateService(MailProperties properties, ResourceLoader resources) throws IOException {
        signature = properties.signature();
        Map<String, Template> loaded = new TreeMap<>();
        if (properties.templates() == null || properties.templates().isEmpty())
            throw new IllegalStateException("Configure at least one mail template");
        for (var entry : properties.templates().entrySet()) {
            var definition = entry.getValue();
            if (!entry.getKey().matches("[a-z][a-z0-9-]{0,63}") || definition.subject() == null
                    || definition.subject().isBlank() || definition.subject().contains("\r") || definition.subject().contains("\n"))
                throw new IllegalStateException("Invalid mail template definition");
            String html = read(resources, definition.html());
            String text = read(resources, definition.text());
            if (!html.contains("{{signature}}") || !text.contains("{{signature}}"))
                throw new IllegalStateException("Every email template must include the managed signature in HTML and text");
            Set<String> variables = new TreeSet<>();
            for (String source : List.of(definition.subject(), html, text)) {
                var matcher = VARIABLE.matcher(source);
                while (matcher.find()) variables.add(matcher.group(1));
                String remaining = VARIABLE.matcher(source).replaceAll("");
                if (remaining.contains("{{") || remaining.contains("}}"))
                    throw new IllegalStateException("Invalid mail template placeholder");
            }
            variables.remove("signature");
            loaded.put(entry.getKey(), new Template(definition.subject(), html, text,
                    Collections.unmodifiableSet(variables)));
        }
        templates = Collections.unmodifiableMap(loaded);
    }

    private static String read(ResourceLoader loader, String location) throws IOException {
        if (location == null || location.isBlank()) throw new IllegalStateException("Missing mail template resource");
        try (var input = loader.getResource(location).getInputStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public List<TemplateResponse> list() {
        return templates.entrySet().stream().map(e -> new TemplateResponse(e.getKey(),
                e.getValue().subject(), e.getValue().variables())).toList();
    }

    public RenderedMail render(String id, Map<String, String> variables) {
        Template template = templates.get(id);
        if (template == null) throw new ApiException(MailCode.TEMPLATE_NOT_FOUND);
        if (variables == null || !variables.keySet().equals(template.variables())
                || variables.values().stream().anyMatch(v -> v == null || v.isBlank() || v.length() > 4096))
            throw new ApiException(MailCode.TEMPLATE_VARIABLES_INVALID);
        Map<String, String> context = new HashMap<>(variables);
        context.put("signature", signature);
        String subject = substitute(template.subject(), context, false);
        if (subject.contains("\r") || subject.contains("\n"))
            throw new ApiException(MailCode.TEMPLATE_VARIABLES_INVALID);
        return new RenderedMail(subject, substitute(template.html(), context, true),
                substitute(template.text(), context, false));
    }

    private static String substitute(String source, Map<String, String> variables, boolean html) {
        return VARIABLE.matcher(source).replaceAll(match -> {
            String value = variables.get(match.group(1));
            return java.util.regex.Matcher.quoteReplacement(html ? HtmlUtils.htmlEscape(value, "UTF-8") : value);
        });
    }
}
