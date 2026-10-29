package dev.kaidev.common.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public final class ServletApi {
    private ServletApi() {}
    public static String traceId() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)
            return traceId(attributes.getRequest());
        return RequestTrace.resolve(null);
    }
    public static String traceId(HttpServletRequest request) {
        Object value = request.getAttribute(RequestTrace.ATTRIBUTE);
        if (value != null) return value.toString();
        String trace = RequestTrace.resolve(request.getHeader(RequestTrace.HEADER));
        request.setAttribute(RequestTrace.ATTRIBUTE, trace);
        return trace;
    }
    public static <T> ApiResponse<T> success(ApiCode code, T data) {
        return ApiResponse.success(code, data, traceId());
    }
    public static void failure(HttpServletRequest request, HttpServletResponse response,
            ObjectMapper mapper, ApiCode code) throws IOException {
        response.setStatus(code.status().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(RequestTrace.HEADER, traceId(request));
        mapper.writeValue(response.getOutputStream(), ApiResponse.failure(code, List.of(), traceId(request)));
    }
}
