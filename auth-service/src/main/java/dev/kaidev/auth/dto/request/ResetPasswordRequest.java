package dev.kaidev.auth.dto.request;

import dev.kaidev.common.validation.annotation.ValidPassword;
import jakarta.validation.constraints.*;

public record ResetPasswordRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") String token,
        @ValidPassword String newPassword) {
    @Override public String toString() { return "ResetPasswordRequest[REDACTED]"; }
}
