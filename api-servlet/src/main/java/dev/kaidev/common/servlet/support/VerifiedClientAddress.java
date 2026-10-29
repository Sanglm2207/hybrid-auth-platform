package dev.kaidev.common.servlet.support;

import dev.kaidev.common.security.ClientIdentity;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;

public final class VerifiedClientAddress {
    private VerifiedClientAddress() {}
    public static String resolve(HttpServletRequest request, String key) {
        if (Collections.list(request.getHeaders(ClientIdentity.IP)).size() == 1
                && Collections.list(request.getHeaders(ClientIdentity.TIME)).size() == 1
                && Collections.list(request.getHeaders(ClientIdentity.SIGNATURE)).size() == 1
                && ClientIdentity.verify(key, request.getHeader(ClientIdentity.IP), request.getHeader(ClientIdentity.TIME),
                        request.getHeader(ClientIdentity.SIGNATURE), request.getMethod(), request.getRequestURI()))
            return request.getHeader(ClientIdentity.IP);
        return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
    }
}
