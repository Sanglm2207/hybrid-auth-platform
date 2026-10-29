package dev.kaidev.mail.dto;

import dev.kaidev.common.util.EmailAddress;
import dev.kaidev.common.validation.annotation.ValidEmail;
import jakarta.validation.constraints.*;
import java.util.Map;

public record SendMailRequest(
        @ValidEmail String to,
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9-]{0,63}") String templateId,
        @NotNull @Size(max = 32) Map<@Pattern(regexp = "[a-zA-Z][a-zA-Z0-9_]{0,63}") String,
                @NotBlank @Size(max = 4096) String> variables) {
    public SendMailRequest { to = EmailAddress.normalize(to); }
    @Override public String toString() { return "SendMailRequest[REDACTED]"; }
}
