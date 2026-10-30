package dev.kaidev.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class InternalProfileConfig {
    @Bean @Order(0)
    SecurityFilterChain internalProfileChain(HttpSecurity http, ObjectMapper mapper,
            @Value("${app.identity.api-key:}") String key) throws Exception {
        var filter = new OncePerRequestFilter() {
            @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                    throws IOException, ServletException {
                if (key.length() < 32) { ServletApi.failure(request, response, mapper, CommonCode.SERVICE_UNAVAILABLE); return; }
                var supplied = Collections.list(request.getHeaders("X-Identity-Service-Key"));
                if (supplied.size() != 1 || !MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), supplied.getFirst().getBytes(StandardCharsets.UTF_8))) {
                    ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED); return;
                }
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new UsernamePasswordAuthenticationToken("identity-client", null, List.of()));
                SecurityContextHolder.setContext(context); chain.doFilter(request, response);
            }
        };
        return http.securityMatcher("/internal/**").csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).requestCache(c -> c.disable())
                .authorizeHttpRequests(a -> a.anyRequest().authenticated()).addFilterBefore(filter, AuthorizationFilter.class).build();
    }
}
