package dev.kaidev.auth.api.request;

import dev.kaidev.common.validation.*;
import jakarta.validation.constraints.*;

public record EmailRequest(@ValidEmail String email) {
    public EmailRequest { email = dev.kaidev.common.validation.EmailAddress.normalize(email); }
    @Override public String toString() { return "EmailRequest[email=[REDACTED]]"; }
}
