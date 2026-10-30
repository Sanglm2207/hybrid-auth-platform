package dev.kaidev.gateway.config;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.resilience.DependencyGuard;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import reactor.core.publisher.Mono;

@Configuration
public class GatewayResilience {
    /** Reactor Netty otherwise transparently retries a TCP-aborted request once. */
    @Bean HttpClientCustomizer noTransportRetry(org.springframework.cloud.gateway.config.HttpClientProperties properties) {
        return client -> client.disableRetry(true).responseTimeout(properties.getResponseTimeout());
    }

    @Bean GlobalFilter dependencyCircuitBreaker() { return new RouteBreaker(); }

    static final class RouteBreaker implements GlobalFilter, Ordered {
        private final Map<String, DependencyGuard> guards = new ConcurrentHashMap<>();
        @Override public int getOrder() { return -2; }
        @Override public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange,
                org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            if (route == null) return chain.filter(exchange);
            // Export/deletion share the Auth dependency, even though they have separate route IDs.
            String name = route.getId().equals("user-service-v1") ? "user" : "auth";
            var breaker = guards.computeIfAbsent(name, DependencyGuard::new).breaker();
            return Mono.defer(() -> {
                if (!breaker.tryAcquirePermission()) return Mono.error(new ApiException(CommonCode.SERVICE_UNAVAILABLE));
                long started = System.nanoTime();
                return chain.filter(exchange).doOnSuccess(ignored -> {
                    var status = exchange.getResponse().getStatusCode();
                    if (status != null && status.is5xxServerError())
                        breaker.onError(System.nanoTime() - started, TimeUnit.NANOSECONDS, new IllegalStateException("Upstream failure"));
                    else breaker.onSuccess(System.nanoTime() - started, TimeUnit.NANOSECONDS);
                }).doOnError(error -> breaker.onError(System.nanoTime() - started, TimeUnit.NANOSECONDS, error))
                        .doOnCancel(breaker::releasePermission);
            });
        }
    }
}
