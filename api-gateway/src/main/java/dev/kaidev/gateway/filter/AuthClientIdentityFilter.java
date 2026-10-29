package dev.kaidev.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.reactive.support.ReactiveApi;
import dev.kaidev.common.security.ClientIdentity;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;

@Component
public class AuthClientIdentityFilter implements WebFilter, Ordered {
    private final String key;
    private final ObjectMapper mapper;
    public AuthClientIdentityFilter(@Value("${app.auth-proxy-key:}") String key, ObjectMapper mapper) {
        this.key = key; this.mapper = mapper;
    }
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 20; }
    @Override public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var request = exchange.getRequest();
        String path;
        try { path = org.springframework.web.util.UriUtils.decode(request.getURI().getRawPath(), java.nio.charset.StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { return ReactiveApi.failure(exchange, mapper, CommonCode.INVALID_REQUEST); }
        boolean auth = path.startsWith(ApiPaths.AUTH_V1 + "/");
        if (auth && (key.length() < 32 || request.getRemoteAddress() == null))
            return ReactiveApi.failure(exchange, mapper, CommonCode.SERVICE_UNAVAILABLE);
        var forwarded = request.mutate().headers(headers -> {
            headers.remove(ClientIdentity.IP); headers.remove(ClientIdentity.TIME); headers.remove(ClientIdentity.SIGNATURE);
            if (auth) {
                String ip = request.getRemoteAddress().getAddress().getHostAddress();
                String time = Long.toString(Instant.now().getEpochSecond());
                headers.set(ClientIdentity.IP, ip); headers.set(ClientIdentity.TIME, time);
                headers.set(ClientIdentity.SIGNATURE, ClientIdentity.sign(key, ip, time,
                        request.getMethod().name(), request.getURI().getRawPath()));
            }
        }).build();
        return chain.filter(exchange.mutate().request(forwarded).build());
    }
}
