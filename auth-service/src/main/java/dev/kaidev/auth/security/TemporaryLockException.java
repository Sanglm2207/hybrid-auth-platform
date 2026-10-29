package dev.kaidev.auth.security;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.exception.ApiException;
import org.springframework.http.HttpHeaders;

public class TemporaryLockException extends ApiException {
    private final long retryMs;
    public TemporaryLockException(long retryMs) {
        super(AuthCode.ACCOUNT_TEMPORARILY_LOCKED);
        this.retryMs = retryMs;
    }
    @Override public HttpHeaders getHeaders() {
        var headers = new HttpHeaders();
        headers.set("Retry-After", Long.toString(Math.max(1, (retryMs + 999) / 1000)));
        return HttpHeaders.readOnlyHttpHeaders(headers);
    }
}
