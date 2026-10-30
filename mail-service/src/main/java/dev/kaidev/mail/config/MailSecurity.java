package dev.kaidev.mail.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.servlet.security.ServletSecurityErrors;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.mail.constant.MailCode;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableConfigurationProperties(MailProperties.class)
public class MailSecurity {
    @Bean
    SecurityFilterChain mailSecurityChain(HttpSecurity http, MailProperties properties,
            ObjectMapper mapper, ServletSecurityErrors errors) throws Exception {
        var keyFilter = new OncePerRequestFilter() {
            @Override protected boolean shouldNotFilter(HttpServletRequest request) {
                String path = request.getRequestURI().substring(request.getContextPath().length());
                return path.equals("/actuator/health") || path.equals("/actuator/health/liveness") || path.equals("/actuator/health/readiness") || path.equals("/error");
            }
            @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                    FilterChain chain) throws ServletException, IOException {
                String expected = properties.apiKey();
                if (expected == null || expected.isBlank()) {
                    ServletApi.failure(request, response, mapper, MailCode.MAIL_NOT_CONFIGURED);
                    return;
                }
                var keys = Collections.list(request.getHeaders("X-Mail-Service-Key"));
                if (keys.size() != 1 || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                        keys.getFirst().getBytes(StandardCharsets.UTF_8))) {
                    ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED);
                    return;
                }
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new UsernamePasswordAuthenticationToken("mail-client", null, List.of()));
                SecurityContextHolder.setContext(context);
                chain.doFilter(request, response);
            }
        };
        return http.csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(errors).accessDeniedHandler(errors))
                .authorizeHttpRequests(a -> a.requestMatchers("/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness", "/error").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(keyFilter, AuthorizationFilter.class).build();
    }
}
