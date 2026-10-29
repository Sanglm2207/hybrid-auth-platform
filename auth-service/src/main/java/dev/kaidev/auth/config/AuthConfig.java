package dev.kaidev.auth.config;

import dev.kaidev.common.servlet.security.ServletSecurityErrors;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.nio.file.*;
import java.security.spec.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;

@Configuration
public class AuthConfig {
  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }

  @Bean
  RSAKey rsaKey(@Value("${app.private-key}") String keyPath, @Value("${app.public-key}") String pubPath)
      throws Exception {
    String priv = Files.readString(Path.of(keyPath))
        .replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\\s", "");
    String pub = Files.readString(Path.of(pubPath))
        .replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s", "");
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return new RSAKey.Builder(
        (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(java.util.Base64.getDecoder().decode(pub))))
        .privateKey(
            (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(priv))))
        .keyID("local-1").build();
  }

  @Bean
  JWKSource<SecurityContext> jwkSource(RSAKey key) {
    return (selector, ctx) -> selector.select(new JWKSet(key));
  }

  @Bean
  JwtEncoder jwtEncoder(JWKSource<SecurityContext> source) {
    return new NimbusJwtEncoder(source);
  }

  @Bean
  JwtDecoder jwtDecoder(RSAKey key, @Value("${app.issuer}") String issuer) throws JOSEException {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
        new JwtClaimValidator<java.util.List<String>>("aud", a -> a != null && a.contains("hybrid-api"))));
    return decoder;
  }

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http, ServletSecurityErrors errors) throws Exception {
    return http.csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(errors).accessDeniedHandler(errors))
        .authorizeHttpRequests(a -> a.requestMatchers("/auth/register", "/auth/verify-email", "/auth/resend-otp", "/auth/login", "/auth/refresh", "/auth/logout",
            "/.well-known/jwks.json", "/actuator/health", "/error").permitAll().anyRequest().authenticated())
        .oauth2ResourceServer(o -> o.authenticationEntryPoint(errors).accessDeniedHandler(errors).jwt(j -> {
        })).build();
  }
}
