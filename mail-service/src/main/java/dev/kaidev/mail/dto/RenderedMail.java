package dev.kaidev.mail.dto;

public record RenderedMail(String subject, String html, String text) {
    @Override public String toString() { return "RenderedMail[REDACTED]"; }
}
