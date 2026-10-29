package dev.kaidev.auth.api.request;

import dev.kaidev.common.validation.*;
import jakarta.validation.constraints.*;

public record VerifyEmailRequest(@ValidEmail String email, @NotBlank(message = "OTP is required") @Pattern(regexp = "[0-9]{6}", message = "OTP must contain exactly 6 digits") String otp) {
    public VerifyEmailRequest { email = dev.kaidev.common.validation.EmailAddress.normalize(email); }
    @Override public String toString() { return "VerifyEmailRequest[email=[REDACTED], otp=[REDACTED]]"; }
}
