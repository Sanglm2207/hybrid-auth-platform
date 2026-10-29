package dev.kaidev.common.servlet.security;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.security.SecurityAudit;
import dev.kaidev.common.servlet.support.ServletApi;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

public class ServletSecurityErrors implements AuthenticationEntryPoint, AccessDeniedHandler {
    private final ObjectMapper mapper;
    public ServletSecurityErrors(ObjectMapper mapper) { this.mapper = mapper; }
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        SecurityAudit.record(SecurityAudit.Event.AUTHENTICATION_FAILURE, SecurityAudit.Outcome.DENIED, null, ServletApi.traceId(request));
        response.setHeader("WWW-Authenticate", "Bearer");
        ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED);
    }
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        SecurityAudit.record(SecurityAudit.Event.ACCESS_DENIED, SecurityAudit.Outcome.DENIED, null, ServletApi.traceId(request));
        ServletApi.failure(request, response, mapper, CommonCode.ACCESS_DENIED);
    }
}
