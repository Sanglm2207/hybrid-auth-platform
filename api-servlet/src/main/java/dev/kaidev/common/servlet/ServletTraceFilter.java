package dev.kaidev.common.servlet;

import dev.kaidev.common.api.*;
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
        String previous = MDC.get("traceId");
        MDC.put("traceId", trace);
        response.setHeader(RequestTrace.HEADER, trace);
        long started = System.nanoTime();
        try { chain.doFilter(request, response); }
        finally {
            ApiLog.completed(request.getMethod(), response.getStatus(), (System.nanoTime() - started) / 1_000_000, trace);
            if (previous == null) MDC.remove("traceId"); else MDC.put("traceId", previous);
        }
    }
}
