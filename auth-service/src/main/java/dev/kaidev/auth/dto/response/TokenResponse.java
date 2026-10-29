package dev.kaidev.auth.dto.response;
public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {
    @Override public String toString() { return "TokenResponse[tokens=[REDACTED]]"; }
}
