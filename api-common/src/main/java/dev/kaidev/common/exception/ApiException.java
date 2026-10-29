package dev.kaidev.common.exception;

import dev.kaidev.common.api.code.ApiCode;

import org.springframework.web.server.ResponseStatusException;

public class ApiException extends ResponseStatusException {
    private final ApiCode apiCode;
    public ApiException(ApiCode code) {
        super(code.status(), code.message());
        this.apiCode = code;
    }
    public ApiCode apiCode() { return apiCode; }
}
