package dev.kaidev.common.reactive.filter;

import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.reactive.exception.ReactiveExceptionHandler;
import dev.kaidev.common.reactive.support.ReactiveApi;
import dev.kaidev.common.trace.RequestTrace;

import org.springframework.core.Ordered;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;

public class ReactiveTraceFilter implements WebFilter, Ordered {
    public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String trace = ReactiveApi.traceId(exchange);
        exchange.getResponse().getHeaders().set(RequestTrace.HEADER, trace);
        ServerWebExchange traced = exchange.mutate().request(request -> request.headers(headers -> headers.set(RequestTrace.HEADER, trace))).build();
        long started = System.nanoTime();
        return chain.filter(traced)
                .doOnError(error -> exchange.getAttributes().put("api.failure.status", ReactiveExceptionHandler.code(error).status().value()))
                .doFinally(signal -> {
                    int status = exchange.getResponse().getStatusCode() == null
                            ? (int) exchange.getAttributes().getOrDefault("api.failure.status", 200)
                            : exchange.getResponse().getStatusCode().value();
                    ApiLog.completed(exchange.getRequest().getMethod().name(), status, (System.nanoTime() - started) / 1_000_000, trace);
                });
    }
}
