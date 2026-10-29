package dev.kaidev.gateway.filter;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.reactive.support.ReactiveApi;
import dev.kaidev.common.trace.RequestTrace;
import dev.kaidev.gateway.config.properties.GatewayAccessProperties;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Locale;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.*;
import org.springframework.web.cors.reactive.DefaultCorsProcessor;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;

@Component
public class GatewayAccessFilter implements WebFilter, Ordered {
    private final GatewayAccessProperties properties;
    private final ObjectMapper mapper;
    private final CorsConfiguration cors = new CorsConfiguration();
    private final DefaultCorsProcessor processor = new DefaultCorsProcessor() {
        @Override protected void rejectRequest(ServerHttpResponse response) { response.setStatusCode(HttpStatus.FORBIDDEN); }
    };

    public GatewayAccessFilter(GatewayAccessProperties properties, ObjectMapper mapper) {
        this.properties = properties;
        this.mapper = mapper;
        cors.setAllowedOrigins(properties.allowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization", "Content-Type", RequestTrace.HEADER));
        cors.setExposedHeaders(List.of(RequestTrace.HEADER));
        cors.setAllowCredentials(false);
        cors.setMaxAge(600L);
    }
    public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 10; }

    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        try {
            if (headers.getOrEmpty(HttpHeaders.HOST).size() != 1)
                return reject(exchange, CommonCode.HOST_NOT_ALLOWED);
            InetSocketAddress address = headers.getHost();
            if (address == null || !properties.allowedHosts().contains(address.getHostString().toLowerCase(Locale.ROOT)))
                return reject(exchange, CommonCode.HOST_NOT_ALLOWED);
        } catch (IllegalArgumentException exception) { return reject(exchange, CommonCode.HOST_NOT_ALLOWED); }

        List<String> origins = headers.getOrEmpty(HttpHeaders.ORIGIN);
        if (origins.size() > 1 || (!origins.isEmpty() && !properties.allowedOrigins().contains(origins.getFirst()))
                || (origins.isEmpty() && properties.requireOrigin()
                        && !(exchange.getRequest().getMethod() == HttpMethod.GET
                        && exchange.getRequest().getPath().value().equals("/actuator/health"))))
            return reject(exchange, CommonCode.ORIGIN_NOT_ALLOWED);

        if (!processor.process(cors, exchange)) return reject(exchange, CommonCode.CORS_REJECTED);
        if (CorsUtils.isPreFlightRequest(exchange.getRequest())) {
            exchange.getResponse().setStatusCode(HttpStatus.NO_CONTENT);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }

    private Mono<Void> reject(ServerWebExchange exchange, CommonCode code) { return ReactiveApi.failure(exchange, mapper, code); }
}
