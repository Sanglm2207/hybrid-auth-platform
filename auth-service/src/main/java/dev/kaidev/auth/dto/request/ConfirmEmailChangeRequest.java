package dev.kaidev.auth.dto.request;

import jakarta.validation.constraints.*;

public record ConfirmEmailChangeRequest(@NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") String token) {
    @Override public String toString() { return "ConfirmEmailChangeRequest[REDACTED]"; }
}
