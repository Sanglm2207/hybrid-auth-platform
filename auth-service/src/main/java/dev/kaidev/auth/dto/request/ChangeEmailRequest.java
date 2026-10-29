package dev.kaidev.auth.dto.request;

import dev.kaidev.common.util.EmailAddress;
import dev.kaidev.common.validation.annotation.*;

public record ChangeEmailRequest(
        @ValidPassword(min = 1, message = "Current password is required and must contain at most 72 UTF-8 bytes") String currentPassword,
        @ValidEmail String newEmail) {
    public ChangeEmailRequest { newEmail = EmailAddress.normalize(newEmail); }
    @Override public String toString() { return "ChangeEmailRequest[REDACTED]"; }
}
