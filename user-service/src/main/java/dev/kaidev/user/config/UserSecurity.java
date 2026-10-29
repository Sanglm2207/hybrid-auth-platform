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
    SecurityFilterChain chain(HttpSecurity http, ServletSecurityErrors errors) throws Exception {
        return http.csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .authorizeHttpRequests(
                        a -> a.requestMatchers("/actuator/health", "/error").permitAll().anyRequest().authenticated())
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
