package dev.kaidev.auth.api.request;

import dev.kaidev.common.validation.*;
import jakarta.validation.constraints.*;

public record LoginRequest(@ValidEmail String email, @NotBlank(message = "Password is required") @Size(max = 72, message = "Password must contain at most 72 characters") String password) {
    public LoginRequest { email = dev.kaidev.common.validation.EmailAddress.normalize(email); }
    @Override public String toString() { return "LoginRequest[email=[REDACTED], password=[REDACTED]]"; }
}
