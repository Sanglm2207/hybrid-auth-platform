package dev.kaidev.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.reactive.support.ReactiveApi;
import dev.kaidev.common.security.*;
import java.time.Duration;
import java.util.Optional;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;

public class GatewayIdentityFilter implements WebFilter {
    private final WebClient client;
    private final String key;
    private final ObjectMapper mapper;
    public GatewayIdentityFilter(String url, String key, ObjectMapper mapper) {
        client = WebClient.builder().baseUrl(url).build(); this.key = key; this.mapper = mapper;
    }
    @Override public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return exchange.getPrincipal().ofType(JwtAuthenticationToken.class).map(Optional::of).defaultIfEmpty(Optional.empty()).flatMap(auth -> {
            if (auth.isEmpty()) return chain.filter(exchange);
            if (key.length() < 32) return ReactiveApi.failure(exchange, mapper, CommonCode.SERVICE_UNAVAILABLE);
            var authentication = auth.get(); IdentityCheck check;
            try { check = IdentityCheck.fromClaims(authentication.getToken().getClaims()); }
            catch (RuntimeException e) { return ReactiveApi.failure(exchange, mapper, CommonCode.UNAUTHENTICATED); }
            return client.post().uri("/internal/identity/check").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Identity-Service-Key", key).header("X-Request-Id", ReactiveApi.traceId(exchange)).bodyValue(check)
                    .retrieve().bodyToMono(new ParameterizedTypeReference<ApiResponse<IdentityAccess>>() {})
                    .timeout(Duration.ofSeconds(3)).map(response -> {
                        if (!response.success() || response.data() == null || response.data().roles() == null || response.data().permissions() == null)
                            throw new IllegalStateException("Invalid identity acknowledgement");
                        return response.data();
                    }).switchIfEmpty(Mono.error(new IllegalStateException("Missing identity acknowledgement")))
                    .onErrorResume(e -> {
                        SecurityAudit.record(SecurityAudit.Event.SECURITY_STATE_FAILURE, SecurityAudit.Outcome.UNAVAILABLE, authentication.getName(), ReactiveApi.traceId(exchange));
                        return ReactiveApi.failure(exchange, mapper, CommonCode.SERVICE_UNAVAILABLE).then(Mono.empty());
                    })
                    .flatMap(access -> {
                        if (!access.active()) {
                            SecurityAudit.record(SecurityAudit.Event.AUTHENTICATION_FAILURE, SecurityAudit.Outcome.DENIED, authentication.getName(), ReactiveApi.traceId(exchange));
                            return ReactiveApi.failure(exchange, mapper, CommonCode.UNAUTHENTICATED);
                        }
                        var updated = new JwtAuthenticationToken(authentication.getToken(), access.authorities().stream().map(SimpleGrantedAuthority::new).toList());
                        return chain.filter(exchange.mutate().principal(Mono.just(updated)).build())
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(updated));
                    });
        });
    }
}
