package dev.kaidev.common.servlet.config;

import dev.kaidev.common.servlet.controller.ServletFallbackErrorController;
import dev.kaidev.common.servlet.exception.ServletExceptionHandler;
import dev.kaidev.common.servlet.filter.ServletTraceFilter;
import dev.kaidev.common.servlet.security.ServletSecurityErrors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

@AutoConfiguration(before = ErrorMvcAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ServletApiConfiguration {
    /** Driver deadlines also cover an established connection to a paused PostgreSQL server. */
    @Bean static org.springframework.beans.factory.config.BeanPostProcessor postgresDeadlines() {
        return new org.springframework.beans.factory.config.BeanPostProcessor() {
            @Override public Object postProcessBeforeInitialization(Object bean, String name) {
                if (bean instanceof com.zaxxer.hikari.HikariDataSource pool
                        && pool.getJdbcUrl() != null && pool.getJdbcUrl().startsWith("jdbc:postgresql:")) {
                    var properties = pool.getDataSourceProperties();
                    properties.putIfAbsent("connectTimeout", "2");
                    properties.putIfAbsent("socketTimeout", "5");
                    properties.putIfAbsent("tcpKeepAlive", "true");
                    properties.putIfAbsent("options", "-c statement_timeout=5000 -c lock_timeout=2000");
                }
                return bean;
            }
        };
    }

    @Bean
    org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer strictRequestJson() {
        return builder -> builder.featuresToEnable(
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .featuresToDisable(com.fasterxml.jackson.databind.MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .postConfigurer(mapper -> {
                    var coercion = mapper.coercionConfigFor(com.fasterxml.jackson.databind.type.LogicalType.Textual);
                    for (var shape : new com.fasterxml.jackson.databind.cfg.CoercionInputShape[]{
                            com.fasterxml.jackson.databind.cfg.CoercionInputShape.Integer,
                            com.fasterxml.jackson.databind.cfg.CoercionInputShape.Float,
                            com.fasterxml.jackson.databind.cfg.CoercionInputShape.Boolean}) {
                        coercion.setCoercion(shape, com.fasterxml.jackson.databind.cfg.CoercionAction.Fail);
                    }
                    mapper.getFactory().setStreamReadConstraints(com.fasterxml.jackson.core.StreamReadConstraints.builder()
                            .maxNestingDepth(20).maxStringLength(4096).maxNumberLength(128).build());
                });
    }
    @Bean org.springframework.boot.web.client.RestClientCustomizer correlationRestClientCustomizer(){
        return builder->builder.requestInterceptor((request,body,execution)->{
            String id=org.slf4j.MDC.get("correlationId");
            if(id!=null&&!request.getHeaders().containsKey(dev.kaidev.common.trace.RequestTrace.HEADER))
                request.getHeaders().set(dev.kaidev.common.trace.RequestTrace.HEADER,id);
            return execution.execute(request,body);
        });
    }
    @Bean ServletExceptionHandler servletExceptionHandler() { return new ServletExceptionHandler(); }
    @Bean ServletSecurityErrors servletSecurityErrors(ObjectMapper mapper) { return new ServletSecurityErrors(mapper); }
    @Bean FilterRegistrationBean<ServletTraceFilter> servletTraceFilter() {
        FilterRegistrationBean<ServletTraceFilter> bean = new FilterRegistrationBean<>(new ServletTraceFilter());
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 5);
        return bean;
    }
    @Bean @ConditionalOnMissingBean(ErrorController.class)
    ServletFallbackErrorController servletFallbackErrorController() { return new ServletFallbackErrorController(); }
}
