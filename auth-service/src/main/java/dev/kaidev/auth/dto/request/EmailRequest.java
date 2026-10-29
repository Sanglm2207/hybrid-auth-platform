package dev.kaidev.auth.dto.request;

import dev.kaidev.common.validation.annotation.ValidEmail;

import jakarta.validation.constraints.*;

public record EmailRequest(@ValidEmail String email) {
    public EmailRequest { email = dev.kaidev.common.util.EmailAddress.normalize(email); }
    @Override public String toString() { return "EmailRequest[email=[REDACTED]]"; }
}
