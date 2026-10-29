package dev.kaidev.common.reactive.security;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.security.SecurityAudit;
import dev.kaidev.common.reactive.support.ReactiveApi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class ReactiveSecurityErrors implements ServerAuthenticationEntryPoint, ServerAccessDeniedHandler {
    private final ObjectMapper mapper;
    public ReactiveSecurityErrors(ObjectMapper mapper) { this.mapper = mapper; }
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException exception) {
        SecurityAudit.record(SecurityAudit.Event.AUTHENTICATION_FAILURE, SecurityAudit.Outcome.DENIED, null, ReactiveApi.traceId(exchange));
        exchange.getResponse().getHeaders().set("WWW-Authenticate", "Bearer");
        return ReactiveApi.failure(exchange, mapper, CommonCode.UNAUTHENTICATED);
    }
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException exception) {
        SecurityAudit.record(SecurityAudit.Event.ACCESS_DENIED, SecurityAudit.Outcome.DENIED, null, ReactiveApi.traceId(exchange));
        return ReactiveApi.failure(exchange, mapper, CommonCode.ACCESS_DENIED);
    }
}
