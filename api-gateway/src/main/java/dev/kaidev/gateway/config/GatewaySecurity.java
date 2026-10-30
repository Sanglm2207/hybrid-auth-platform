package dev.kaidev.gateway.config;

import dev.kaidev.common.api.ApiPaths;
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
    SecurityWebFilterChain chain(ServerHttpSecurity http, ReactiveSecurityErrors errors,
            com.fasterxml.jackson.databind.ObjectMapper mapper, @Value("${app.identity.url}") String identityUrl,
            @Value("${app.identity.api-key:}") String identityKey,org.springframework.web.reactive.function.client.WebClient.Builder builder) {
        return http.addFilterBefore(new dev.kaidev.gateway.filter.GatewayIdentityFilter(identityUrl, identityKey, mapper,builder),
                org.springframework.security.config.web.server.SecurityWebFiltersOrder.AUTHORIZATION).csrf(ServerHttpSecurity.CsrfSpec::disable).authorizeExchange(x -> x
                .pathMatchers(ApiPaths.AUTH_V1 + "/account-actions.js", ApiPaths.AUTH_V1 + "/service-tokens", ApiPaths.AUTH_V1 + "/register", ApiPaths.AUTH_V1 + "/resend-verification",
                        ApiPaths.AUTH_V1 + "/forgot-password", ApiPaths.AUTH_V1 + "/reset-password", ApiPaths.AUTH_V1 + "/confirm-email-change", ApiPaths.AUTH_V1 + "/verify-email", ApiPaths.AUTH_V1 + "/resend-otp", ApiPaths.AUTH_V1 + "/login", ApiPaths.AUTH_V1 + "/refresh", ApiPaths.AUTH_V1 + "/logout", "/actuator/health")
                .permitAll()
                .pathMatchers(org.springframework.http.HttpMethod.GET, ApiPaths.USERS_V1 + "/me/export").hasAuthority("account:export")
                .pathMatchers(org.springframework.http.HttpMethod.DELETE, ApiPaths.USERS_V1 + "/me").hasAuthority("account:delete")
                .pathMatchers(org.springframework.http.HttpMethod.GET, ApiPaths.USERS_V1 + "/me").hasAuthority("profile:read")
                .pathMatchers(org.springframework.http.HttpMethod.PATCH, ApiPaths.USERS_V1 + "/me").hasAuthority("profile:write")
                .pathMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/users/*").hasAnyAuthority("profile:read","users:read")
                .pathMatchers(org.springframework.http.HttpMethod.PATCH,"/api/v1/users/*").hasAnyAuthority("profile:write","users:update")
                .anyExchange().authenticated()).oauth2ResourceServer(x -> x.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {
                })).build();
    }

    @Bean
    ForwardedHeaderTransformer forwardedHeaderTransformer(@Value("${app.gateway.trusted-proxies:}") String proxies) {
        return new TrustedIngressTransformer(proxies);
    }

    @Bean
    ReactiveJwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer) {
        NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withJwkSetUri(url).build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return d;
    }
}
