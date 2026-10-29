package dev.kaidev.auth.api.request;

import dev.kaidev.common.validation.*;
import jakarta.validation.constraints.*;

public record RefreshRequest(@NotBlank(message = "Refresh token is required") @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Refresh token has an invalid format") String refreshToken) {
    @Override public String toString() { return "RefreshRequest[refreshToken=[REDACTED]]"; }
}
