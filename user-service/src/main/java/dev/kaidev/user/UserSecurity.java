package dev.kaidev.user;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.beans.factory.annotation.Value;
import java.util.List;

@Configuration
public class UserSecurity {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.csrf(c -> c.disable())
                .authorizeHttpRequests(
                        a -> a.requestMatchers("/actuator/health").permitAll().anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(j -> {
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
