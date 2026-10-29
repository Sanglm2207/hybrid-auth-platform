package dev.kaidev.common.reactive.support;

import dev.kaidev.common.api.code.ApiCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.trace.RequestTrace;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public final class ReactiveApi {
    private ReactiveApi() {}
    public static String traceId(ServerWebExchange exchange) {
        return exchange.getAttributes().computeIfAbsent(RequestTrace.ATTRIBUTE,
                ignored -> RequestTrace.resolve(exchange.getRequest().getHeaders().getFirst(RequestTrace.HEADER))).toString();
    }
    public static Mono<Void> failure(ServerWebExchange exchange, ObjectMapper mapper, ApiCode code) {
        if (exchange.getResponse().isCommitted()) return Mono.empty();
        exchange.getResponse().setStatusCode(code.status());
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set(RequestTrace.HEADER, traceId(exchange));
        try {
            byte[] body = mapper.writeValueAsBytes(ApiResponse.failure(code, List.of(), traceId(exchange)));
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
        } catch (JsonProcessingException exception) { return Mono.error(exception); }
    }
}
