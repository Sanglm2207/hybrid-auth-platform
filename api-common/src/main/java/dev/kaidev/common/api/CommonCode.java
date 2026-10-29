package dev.kaidev.common.api;

import org.springframework.http.HttpStatus;

public enum CommonCode implements ApiCode {
    OK(HttpStatus.OK, "Request completed successfully"),
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "Request validation failed"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "Request body or parameters are invalid"),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "A valid access token is required"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "You do not have permission to access this resource"),
    HOST_NOT_ALLOWED(HttpStatus.FORBIDDEN, "Request host is not allowed"),
    ORIGIN_NOT_ALLOWED(HttpStatus.FORBIDDEN, "Request origin is not allowed"),
    CORS_REJECTED(HttpStatus.FORBIDDEN, "Cross-origin method or headers are not allowed"),
    NOT_FOUND(HttpStatus.NOT_FOUND, "Resource not found"),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "HTTP method is not allowed"),
    CONFLICT(HttpStatus.CONFLICT, "The request conflicts with existing data"),
    PAYLOAD_TOO_LARGE(HttpStatus.PAYLOAD_TOO_LARGE, "Request body is too large"),
    UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Content type is not supported"),
    TOO_MANY_REQUESTS(HttpStatus.TOO_MANY_REQUESTS, "Too many requests"),
    UPSTREAM_UNAVAILABLE(HttpStatus.BAD_GATEWAY, "Upstream service is unavailable"),
    UPSTREAM_TIMEOUT(HttpStatus.GATEWAY_TIMEOUT, "Upstream service timed out"),
    SERVICE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Service is temporarily unavailable"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");

    private final HttpStatus status;
    private final String message;
    CommonCode(HttpStatus status, String message) { this.status = status; this.message = message; }
    public HttpStatus status() { return status; }
    public String message() { return message; }

    public static CommonCode fromStatus(int status) {
        for (CommonCode code : values()) {
            if (code.status.value() == status && code != VALIDATION_FAILED
                    && code != HOST_NOT_ALLOWED && code != ORIGIN_NOT_ALLOWED && code != CORS_REJECTED)
                return code;
        }
        return status >= 500 ? INTERNAL_ERROR : INVALID_REQUEST;
    }
}
