package dev.kaidev.gateway;

import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import java.util.List;

@Configuration
public class GatewaySecurity {
    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable).authorizeExchange(x -> x
                .pathMatchers("/auth/register", "/auth/verify-email", "/auth/resend-otp", "/auth/login", "/auth/refresh", "/auth/logout", "/actuator/health")
                .permitAll().anyExchange().authenticated()).oauth2ResourceServer(x -> x.jwt(j -> {
                })).build();
    }

    @Bean
    ReactiveJwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer) {
        NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withJwkSetUri(url).build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return d;
    }
}
