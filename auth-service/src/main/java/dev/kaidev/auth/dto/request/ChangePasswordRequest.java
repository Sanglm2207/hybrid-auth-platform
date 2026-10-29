package dev.kaidev.auth.dto.request;

import dev.kaidev.common.validation.annotation.ValidPassword;

public record ChangePasswordRequest(
        @ValidPassword(min = 1, message = "Current password is required and must contain at most 72 UTF-8 bytes") String currentPassword,
        @ValidPassword String newPassword) {
    @Override public String toString() { return "ChangePasswordRequest[REDACTED]"; }
}
