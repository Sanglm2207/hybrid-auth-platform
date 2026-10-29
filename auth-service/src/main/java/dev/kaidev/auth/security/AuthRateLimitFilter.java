package dev.kaidev.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.ClientIdentity;
import dev.kaidev.common.security.SecurityAudit;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.Collections;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthRateLimitFilter extends OncePerRequestFilter {
    private final AbuseProtection protection;
    private final ObjectMapper mapper;
    private final String proxyKey;

    public AuthRateLimitFilter(AbuseProtection protection, ObjectMapper mapper, String proxyKey) {
        this.protection = protection; this.mapper = mapper; this.proxyKey = proxyKey;
    }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        // Cover encoded aliases and unknown POST paths as well as normal controller mappings.
        return !request.getMethod().equals("POST") || request.getRequestURI().startsWith(request.getContextPath() + "/internal/");
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String ip = request.getRemoteAddr();
        String path = request.getRequestURI().substring(request.getContextPath().length());
        try { path = org.springframework.web.util.UriUtils.decode(path, java.nio.charset.StandardCharsets.UTF_8); }
        catch (IllegalArgumentException ignored) { path = "/invalid"; }
        ip = dev.kaidev.common.servlet.support.VerifiedClientAddress.resolve(request, proxyKey);
        try {
            long retry = protection.rateLimit(ip == null ? "unknown" : ip, path.equals(ApiPaths.AUTH_V1 + "/login"));
            if (retry > 0) {
                response.setHeader("Retry-After", Long.toString(Math.max(1, (retry + 999) / 1000)));
                SecurityAudit.record(SecurityAudit.Event.RATE_LIMITED, SecurityAudit.Outcome.DENIED, null, ServletApi.traceId(request));
                ServletApi.failure(request, response, mapper, AuthCode.RATE_LIMITED);
                return;
            }
        } catch (ApiException e) { ServletApi.failure(request, response, mapper, e.apiCode()); return; }
        chain.doFilter(request, response);
    }
}
