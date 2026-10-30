package dev.kaidev.common.reactive.exception;

import dev.kaidev.common.api.code.ApiCode;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.reactive.support.ReactiveApi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.Ordered;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;

public class ReactiveExceptionHandler implements WebExceptionHandler, Ordered {
    private final ObjectMapper mapper;
    public ReactiveExceptionHandler(ObjectMapper mapper) { this.mapper = mapper; }
    public int getOrder() { return -2; }
    public Mono<Void> handle(ServerWebExchange exchange, Throwable exception) {
        if (exchange.getResponse().isCommitted()) return Mono.error(exception);
        ApiCode code = code(exception);
        if (exchange.getRequest().getPath().value().equals("/api/v1/auth/refresh")
                && (code == CommonCode.UPSTREAM_TIMEOUT || code == CommonCode.UPSTREAM_UNAVAILABLE)) {
            // The server may have committed rotation before the response was lost.
            exchange.getResponse().getHeaders().set("X-Refresh-Outcome", "unknown");
            exchange.getResponse().getHeaders().set("Cache-Control", "no-store");
        }
        if (code.status().is5xxServerError()) ApiLog.failure(code.name(), exception, ReactiveApi.traceId(exchange));
        return ReactiveApi.failure(exchange, mapper, code);
    }
    public static ApiCode code(Throwable error) {
        if (error instanceof ApiException api) return api.apiCode();
        if (error instanceof ResponseStatusException status) return CommonCode.fromStatus(status.getStatusCode().value());
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof java.util.concurrent.TimeoutException
                    || cause.getClass().getSimpleName().contains("TimeoutException")) return CommonCode.UPSTREAM_TIMEOUT;
            if (cause instanceof java.net.ConnectException || cause instanceof java.net.UnknownHostException
                    || cause.getClass().getSimpleName().equals("PrematureCloseException")) return CommonCode.UPSTREAM_UNAVAILABLE;
            if (cause.getCause() == cause) break;
        }
        return CommonCode.INTERNAL_ERROR;
    }
}
