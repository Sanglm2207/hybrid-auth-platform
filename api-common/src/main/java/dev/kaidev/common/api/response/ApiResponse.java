package dev.kaidev.common.api.response;

import dev.kaidev.common.api.code.ApiCode;

import java.time.Instant;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public record ApiResponse<T>(boolean success, String code, String message, T data,
        List<FieldViolation> errors, String traceId, Instant timestamp) {
    public static <T> ApiResponse<T> success(ApiCode code, T data, String traceId) {
        return new ApiResponse<>(true, code.name(), code.message(), data, List.of(), traceId, Instant.now());
    }
    public static ApiResponse<Void> failure(ApiCode code, List<FieldViolation> errors, String traceId) {
        return new ApiResponse<>(false, code.name(), code.message(), null, List.copyOf(errors), traceId, Instant.now());
    }
}
