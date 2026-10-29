package dev.kaidev.auth.dto.request;

import dev.kaidev.common.validation.annotation.ValidEmail;
import dev.kaidev.common.validation.annotation.ValidPassword;

import jakarta.validation.constraints.*;

public record LoginRequest(@ValidEmail String email, @ValidPassword(min = 1, message = "Password is required and must contain at most 72 UTF-8 bytes") String password) {
    public LoginRequest { email = dev.kaidev.common.util.EmailAddress.normalize(email); }
    @Override public String toString() { return "LoginRequest[email=[REDACTED], password=[REDACTED]]"; }
}
