package dev.kaidev.common.servlet;

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
    @Bean
    org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer strictRequestJson() {
        return builder -> builder.featuresToEnable(
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .featuresToDisable(com.fasterxml.jackson.databind.MapperFeature.ALLOW_COERCION_OF_SCALARS);
    }
    @Bean ServletExceptionHandler servletExceptionHandler() { return new ServletExceptionHandler(); }
    @Bean ServletSecurityErrors servletSecurityErrors(ObjectMapper mapper) { return new ServletSecurityErrors(mapper); }
    @Bean FilterRegistrationBean<ServletTraceFilter> servletTraceFilter() {
        FilterRegistrationBean<ServletTraceFilter> bean = new FilterRegistrationBean<>(new ServletTraceFilter());
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
    @Bean @ConditionalOnMissingBean(ErrorController.class)
    ServletFallbackErrorController servletFallbackErrorController() { return new ServletFallbackErrorController(); }
}
