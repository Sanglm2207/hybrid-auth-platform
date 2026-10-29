package dev.kaidev.common.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.CommonCode;
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
        response.setHeader("WWW-Authenticate", "Bearer");
        ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED);
    }
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
            throws IOException {
        ServletApi.failure(request, response, mapper, CommonCode.ACCESS_DENIED);
    }
}
