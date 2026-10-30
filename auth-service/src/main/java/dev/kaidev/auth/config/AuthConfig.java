package dev.kaidev.auth.config;

import dev.kaidev.auth.security.*;
import dev.kaidev.auth.identity.*;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.servlet.security.ServletSecurityErrors;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;

@Configuration
@EnableScheduling
@org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
public class AuthConfig {
    @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }

    @Bean
    public JwtDecoder jwtDecoder(JwtKeyRing keys, @Value("${app.issuer}") String issuer) {
        var processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                (selector, context) -> selector.select(keys.publicKeys())));
        var decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
        return decoder;
    }

    @Bean
    FilterRegistrationBean<AuthRateLimitFilter> authRateLimitFilter(AbuseProtection protection, ObjectMapper mapper,
            @Value("${app.auth-proxy-key:}") String proxyKey) {
        var bean = new FilterRegistrationBean<>(new AuthRateLimitFilter(protection, mapper, proxyKey));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        return bean;
    }

    @Bean
    @org.springframework.core.annotation.Order(1)
    SecurityFilterChain filterChain(HttpSecurity http, ServletSecurityErrors errors, IdentityValidationService identities, ObjectMapper mapper) throws Exception {
        return http.addFilterAfter(new LocalIdentityFilter(identities, mapper), org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class)
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .authorizeHttpRequests(a -> a.requestMatchers(ApiPaths.AUTH_V1 + "/account-actions.js", ApiPaths.AUTH_V1 + "/register", ApiPaths.AUTH_V1 + "/resend-verification",
                        ApiPaths.AUTH_V1 + "/forgot-password", ApiPaths.AUTH_V1 + "/reset-password", ApiPaths.AUTH_V1 + "/confirm-email-change", ApiPaths.AUTH_V1 + "/verify-email",
                        ApiPaths.AUTH_V1 + "/resend-otp", ApiPaths.AUTH_V1 + "/login", ApiPaths.AUTH_V1 + "/refresh",
                        ApiPaths.AUTH_V1 + "/logout", "/.well-known/jwks.json", "/actuator/health", "/error")
                        .permitAll().anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {})).build();
    }
}
