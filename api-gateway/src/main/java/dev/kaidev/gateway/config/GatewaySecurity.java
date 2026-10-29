package dev.kaidev.gateway.config;

import dev.kaidev.common.reactive.security.ReactiveSecurityErrors;
import dev.kaidev.gateway.config.properties.GatewayAccessProperties;

import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;

@Configuration
@EnableConfigurationProperties(GatewayAccessProperties.class)
public class GatewaySecurity {
    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http, ReactiveSecurityErrors errors) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable).authorizeExchange(x -> x
                .pathMatchers("/auth/register", "/auth/verify-email", "/auth/resend-otp", "/auth/login", "/auth/refresh", "/auth/logout", "/actuator/health")
                .permitAll().anyExchange().authenticated()).oauth2ResourceServer(x -> x.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {
                })).build();
    }

    @Bean
    ForwardedHeaderTransformer forwardedHeaderTransformer() {
        ForwardedHeaderTransformer transformer = new ForwardedHeaderTransformer();
        transformer.setRemoveOnly(true);
        return transformer;
    }

    @Bean
    ReactiveJwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer) {
        NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withJwkSetUri(url).build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return d;
    }
}
