package dev.kaidev.auth.dto.response;
import java.util.UUID;
public record RegistrationResponse(UUID id, String email, boolean emailVerified) {}
