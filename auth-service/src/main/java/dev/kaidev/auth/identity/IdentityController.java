package dev.kaidev.auth.identity;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.common.validation.annotation.ValidPassword;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.AUTH_V1)
public class IdentityController {
    public record Reauthenticate(@ValidPassword(min = 1) String currentPassword) {
        @Override public String toString() { return "Reauthenticate[REDACTED]"; }
    }
    public record RolesRequest(@NotEmpty @Size(max = 16) Set<@NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_]{0,31}") String> roles,
            @ValidPassword(min = 1) String currentPassword) {
        @Override public String toString() { return "RolesRequest[REDACTED]"; }
    }
    public record RoleRequest(@NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_]{0,31}") String name,
            @NotNull @Size(max = 8) Set<@NotBlank @Size(max = 64) String> permissions, @ValidPassword(min = 1) String currentPassword) {
        @Override public String toString() { return "RoleRequest[REDACTED]"; }
    }
    private final SessionService sessions;
    private final DeviceRegistry devices;
    private final IdentityManagementService management;
    private final RolePolicyService roles;
    public IdentityController(SessionService sessions, DeviceRegistry devices, IdentityManagementService management, RolePolicyService roles) {
        this.sessions = sessions; this.devices = devices; this.management = management; this.roles = roles;
    }
    @GetMapping("/sessions") @PreAuthorize("hasAuthority('sessions:read')")
    public ApiResponse<List<SessionView>> sessions(@AuthenticationPrincipal Jwt jwt) {
        return ServletApi.success(CommonCode.OK, sessions.list(owner(jwt), UUID.fromString(jwt.getClaimAsString("sid"))));
    }
    @DeleteMapping("/sessions/{id}") @PreAuthorize("hasAuthority('sessions:revoke')")
    public ApiResponse<Void> revoke(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        sessions.revokeSession(owner(jwt), id); return ServletApi.success(AuthCode.SESSION_REVOKED, null);
    }
    @GetMapping("/devices") @PreAuthorize("hasAuthority('devices:read')")
    public ApiResponse<List<DeviceRegistry.DeviceView>> devices(@AuthenticationPrincipal Jwt jwt) {
        UUID owner = owner(jwt);
        return ServletApi.success(CommonCode.OK, devices.list(owner, sessions.list(owner, UUID.fromString(jwt.getClaimAsString("sid")))));
    }
    @DeleteMapping("/devices/{id}") @PreAuthorize("hasAuthority('devices:revoke')")
    public ApiResponse<Void> revokeDevice(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        management.revokeDevice(owner(jwt), id); return ServletApi.success(AuthCode.DEVICE_REVOKED, null);
    }
    @PostMapping("/deactivate") @PreAuthorize("hasAuthority('account:deactivate')")
    public ApiResponse<Void> deactivate(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody Reauthenticate request) {
        management.deactivate(owner(jwt), request.currentPassword()); return ServletApi.success(AuthCode.ACCOUNT_DEACTIVATED, null);
    }
    @GetMapping("/roles") @PreAuthorize("hasAuthority('roles:manage')")
    public ApiResponse<List<RolePolicyService.RoleView>> roles() { return ServletApi.success(CommonCode.OK, roles.list()); }
    @GetMapping("/permissions") @PreAuthorize("hasAuthority('roles:manage')")
    public ApiResponse<Set<String>> permissions() { return ServletApi.success(CommonCode.OK, Permissions.ALL); }
    @PostMapping("/roles") @PreAuthorize("hasAuthority('roles:manage')")
    public ApiResponse<RolePolicyService.RoleView> createRole(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody RoleRequest request) {
        return ServletApi.success(AuthCode.ROLE_UPDATED, management.saveRole(owner(jwt), request.name(), request.permissions(), request.currentPassword(), true));
    }
    @PutMapping("/roles/{name}/permissions") @PreAuthorize("hasAuthority('roles:manage')")
    public ApiResponse<RolePolicyService.RoleView> updateRole(@AuthenticationPrincipal Jwt jwt, @PathVariable String name, @Valid @RequestBody RoleRequest request) {
        if (!name.equals(request.name())) throw new dev.kaidev.common.exception.ApiException(AuthCode.INVALID_ROLE_POLICY);
        return ServletApi.success(AuthCode.ROLE_UPDATED, management.saveRole(owner(jwt), name, request.permissions(), request.currentPassword(), false));
    }
    @PutMapping("/users/{id}/roles") @PreAuthorize("hasAuthority('roles:manage')")
    public ApiResponse<Set<String>> assign(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id, @Valid @RequestBody RolesRequest request) {
        return ServletApi.success(AuthCode.ROLES_UPDATED, management.assignRoles(owner(jwt), id, request.roles(), request.currentPassword()));
    }
    private static UUID owner(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
