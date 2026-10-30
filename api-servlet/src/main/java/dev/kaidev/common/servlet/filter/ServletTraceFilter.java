package dev.kaidev.common.servlet.filter;

import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.common.trace.RequestTrace;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

public class ServletTraceFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String trace = ServletApi.traceId(request);
        String previous = MDC.get("correlationId");
        MDC.put("correlationId", trace);
        response.setHeader(RequestTrace.HEADER, trace);
        long started = System.nanoTime();
        try { chain.doFilter(request, response); }
        finally {
            if("POST".equals(request.getMethod())&&(request.getContextPath()+"/api/v1/auth/login").equals(request.getRequestURI()))
                dev.kaidev.common.observability.SecurityMetrics.login(response.getStatus());
            ApiLog.completed(request.getMethod(), response.getStatus(), (System.nanoTime() - started) / 1_000_000, trace);
            if (previous == null) MDC.remove("correlationId"); else MDC.put("correlationId", previous);
        }
    }
}
