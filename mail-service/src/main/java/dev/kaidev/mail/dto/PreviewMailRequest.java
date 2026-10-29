package dev.kaidev.mail.dto;

import jakarta.validation.constraints.*;
import java.util.Map;

public record PreviewMailRequest(
        @NotNull @Size(max = 32) Map<@Pattern(regexp = "[a-zA-Z][a-zA-Z0-9_]{0,63}") String,
                @NotBlank @Size(max = 4096) String> variables) {
    @Override public String toString() { return "PreviewMailRequest[REDACTED]"; }
}
