package dev.kaidev.auth.access;

import dev.kaidev.auth.identity.*;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.common.validation.annotation.ValidPassword;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.Instant;
import java.util.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AccessController {
    public record Password(@ValidPassword(min=1)String currentPassword){@Override public String toString(){return "Password[REDACTED]";}}
    public record Status(@NotNull Boolean locked,@NotNull Boolean active,@ValidPassword(min=1)String currentPassword){@Override public String toString(){return "Status[REDACTED]";}}
    public record PatchStatus(@NotNull AccountStatus status,@ValidPassword(min=1)String currentPassword){@Override public String toString(){return "PatchStatus[REDACTED]";}}
    public record Trust(@Min(1)@Max(90)int days,@ValidPassword(min=1)String currentPassword){@Override public String toString(){return "Trust[REDACTED]";}}
    public record KeyRequest(@NotBlank @Size(max=100)String name,@NotEmpty @Size(max=4)Set<String> scopes,@NotNull @Future Instant expiresAt,
            @ValidPassword(min=1)String currentPassword){@Override public String toString(){return "KeyRequest[REDACTED]";}}
    public record TokenRequest(@NotBlank @Size(max=8192)String token){@Override public String toString(){return "TokenRequest[REDACTED]";}}
    public record TenantRequest(@NotBlank @Size(max=100)String name,@ValidPassword(min=1)String currentPassword){@Override public String toString(){return "TenantRequest[REDACTED]";}}
    private final UserAdministration users;
    private final ServiceCredentials keys;
    private final LoginHistory history;
    private final DeviceTrust trust;
    private final TokenIntrospection introspection;
    private final dev.kaidev.auth.service.SessionService sessions;
    public AccessController(UserAdministration users,ServiceCredentials keys,LoginHistory history,DeviceTrust trust,TokenIntrospection introspection,dev.kaidev.auth.service.SessionService sessions){
        this.users=users;this.keys=keys;this.history=history;this.trust=trust;this.introspection=introspection;this.sessions=sessions;
    }
    @GetMapping("/users") @PreAuthorize("hasAuthority('users:read')")
    public ApiResponse<?> search(@RequestParam(defaultValue="")String q,@RequestParam(required=false)Boolean locked,
            @RequestParam(required=false)Boolean active,@RequestParam(required=false)AccountStatus status,
            @RequestParam(defaultValue="email,asc")String sort,
            @RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="20")int size){return ok(users.search(q,locked,active,status,sort,page,size));}
    @PatchMapping("/users/{id}/status") @PreAuthorize("hasAuthority('users:update')")
    public ApiResponse<?> patchStatus(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody PatchStatus body){
        return ok(users.status(owner(jwt),id,body.status().locked(),body.status().active(),body.currentPassword()));
    }
    @PutMapping("/users/{id}/status") @PreAuthorize("hasAuthority('users:update')")
    public ApiResponse<?> status(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody Status body){return ok(users.status(owner(jwt),id,body.locked(),body.active(),body.currentPassword()));}
    @GetMapping("/api-keys") @PreAuthorize("hasAuthority('keys:manage')")
    public ApiResponse<?> keys(@AuthenticationPrincipal Jwt jwt){return ok(keys.list(owner(jwt)));}
    @PostMapping("/api-keys") @PreAuthorize("hasAuthority('keys:manage')")
    public ApiResponse<?> createKey(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody KeyRequest body){return ok(keys.create(owner(jwt),body.name(),body.scopes(),body.expiresAt(),body.currentPassword()));}
    @DeleteMapping("/api-keys/{id}") @PreAuthorize("hasAuthority('keys:manage')")
    public ApiResponse<?> revokeKey(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id){keys.revoke(owner(jwt),id);return ok(null);}
    @PostMapping("/service-tokens")
    public ApiResponse<?> serviceToken(@RequestHeader("X-Api-Key")String secret){return ok(keys.exchange(secret));}
    @GetMapping({"/login-history","/authentication-history"}) @PreAuthorize("hasAuthority('history:read')")
    public ApiResponse<?> history(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false)Instant from,@RequestParam(required=false)Instant to,
            @RequestParam(required=false)Boolean successful,@RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="20")int size){return ok(history.list(owner(jwt),from,to,successful,page,size));}
    @PostMapping("/devices/{id}/trust") @PreAuthorize("hasAuthority('devices:trust')")
    public ApiResponse<?> trust(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody Trust body){trust.set(owner(jwt),id,body.days(),body.currentPassword());return ok(null);}
    @DeleteMapping("/devices/{id}/trust") @PreAuthorize("hasAuthority('devices:trust')")
    public ApiResponse<?> untrust(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@Valid @RequestBody Password body){trust.set(owner(jwt),id,0,body.currentPassword());return ok(null);}
    @PostMapping("/introspect") @PreAuthorize("hasAuthority('tokens:introspect')")
    public ApiResponse<?> introspect(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody TokenRequest body){return ok(introspection.inspect(owner(jwt),body.token()));}
    @GetMapping("/session/current") @PreAuthorize("hasAuthority('sessions:read')")
    public ApiResponse<?> currentSession(@AuthenticationPrincipal Jwt jwt){
        UUID id=UUID.fromString(jwt.getClaimAsString("sid"));
        return ok(sessions.list(owner(jwt),id).stream().filter(session->session.id().equals(id)).findFirst()
                .orElseThrow(()->new dev.kaidev.common.exception.ApiException(CommonCode.NOT_FOUND)));
    }
    private static UUID owner(Jwt jwt){return UUID.fromString(jwt.getSubject());}
    private static <T>ApiResponse<T> ok(T data){return ServletApi.success(CommonCode.OK,data);}
}
