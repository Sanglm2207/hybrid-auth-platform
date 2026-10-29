package dev.kaidev.mail.dto;

import java.util.Set;

public record TemplateResponse(String id, String subject, Set<String> variables) {}
