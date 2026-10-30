package dev.kaidev.user.config;

import dev.kaidev.common.servlet.security.ServletSecurityErrors;

import org.springframework.context.annotation.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.beans.factory.annotation.Value;
import java.util.List;

@Configuration
public class UserSecurity {
    @Bean
    SecurityFilterChain chain(HttpSecurity http, ServletSecurityErrors errors, dev.kaidev.user.security.UserIdentityClient identities,
            com.fasterxml.jackson.databind.ObjectMapper mapper) throws Exception {
        return http.addFilterAfter(new dev.kaidev.user.security.UserIdentityFilter(identities, mapper),
                org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class).csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .authorizeHttpRequests(
                        a -> a.requestMatchers("/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness", "/error").permitAll()
                            .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/v1/users/me").hasAuthority("profile:read")
                            .requestMatchers(org.springframework.http.HttpMethod.PATCH, "/api/v1/users/me").hasAuthority("profile:write")
                            .requestMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/users/*").hasAnyAuthority("profile:read","users:read")
                            .requestMatchers(org.springframework.http.HttpMethod.PATCH,"/api/v1/users/*").hasAnyAuthority("profile:write","users:update")
                            .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {
                })).build();
    }

    JwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer) {
        return decoder(url, issuer, new org.springframework.boot.web.client.RestTemplateBuilder());
    }

    @Bean
    JwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer,
            org.springframework.boot.web.client.RestTemplateBuilder builder) {
        var operations = builder.connectTimeout(java.time.Duration.ofSeconds(2))
                .readTimeout(java.time.Duration.ofSeconds(3)).build();
        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(url).restOperations(operations).build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return d;
    }
}
