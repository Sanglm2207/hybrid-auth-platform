package dev.kaidev.auth.api.request;

import dev.kaidev.common.validation.*;
import jakarta.validation.constraints.*;

public record RegisterRequest(@ValidEmail String email, @ValidPassword String password) {
    public RegisterRequest { email = dev.kaidev.common.validation.EmailAddress.normalize(email); }
    @Override public String toString() { return "RegisterRequest[email=[REDACTED], password=[REDACTED]]"; }
}
