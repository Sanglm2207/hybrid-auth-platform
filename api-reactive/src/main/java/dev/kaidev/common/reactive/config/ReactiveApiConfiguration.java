package dev.kaidev.common.reactive.config;

import dev.kaidev.common.reactive.exception.ReactiveExceptionHandler;
import dev.kaidev.common.reactive.filter.ReactiveTraceFilter;
import dev.kaidev.common.reactive.security.ReactiveSecurityErrors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class ReactiveApiConfiguration {
    @Bean ReactiveSecurityErrors reactiveSecurityErrors(ObjectMapper mapper) { return new ReactiveSecurityErrors(mapper); }
    @Bean ReactiveExceptionHandler reactiveExceptionHandler(ObjectMapper mapper) { return new ReactiveExceptionHandler(mapper); }
    @Bean ReactiveTraceFilter reactiveTraceFilter() { return new ReactiveTraceFilter(); }
}
