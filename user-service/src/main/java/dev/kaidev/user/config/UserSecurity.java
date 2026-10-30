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
                        a -> a.requestMatchers("/actuator/health", "/error").permitAll()
                            .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/v1/users/me").hasAuthority("profile:read")
                            .requestMatchers(org.springframework.http.HttpMethod.PATCH, "/api/v1/users/me").hasAuthority("profile:write")
                            .requestMatchers(org.springframework.http.HttpMethod.GET,"/api/v1/users/*").hasAnyAuthority("profile:read","users:read")
                            .requestMatchers(org.springframework.http.HttpMethod.PATCH,"/api/v1/users/*").hasAnyAuthority("profile:write","users:update")
                            .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {
                })).build();
    }

    @Bean
    JwtDecoder decoder(@Value("${app.jwks-uri}") String url, @Value("${app.issuer}") String issuer) {
        NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(url).build();
        d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return d;
    }
}
