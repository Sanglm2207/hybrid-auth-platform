package dev.kaidev.auth.dto.request;

import dev.kaidev.common.validation.annotation.ValidEmail;
import dev.kaidev.common.validation.annotation.ValidPassword;

import jakarta.validation.constraints.*;

public record RegisterRequest(@ValidEmail String email, @ValidPassword String password) {
    public RegisterRequest { email = dev.kaidev.common.util.EmailAddress.normalize(email); }
    @Override public String toString() { return "RegisterRequest[email=[REDACTED], password=[REDACTED]]"; }
}
