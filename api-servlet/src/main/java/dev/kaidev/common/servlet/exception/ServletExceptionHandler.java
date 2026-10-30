package dev.kaidev.common.servlet.exception;

import dev.kaidev.common.api.code.ApiCode;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.api.response.FieldViolation;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.servlet.support.ServletApi;

import jakarta.validation.ConstraintViolationException;
import java.util.List;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ServletExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(ApiException.class)
    ResponseEntity<Object> business(ApiException exception) {
        return ResponseEntity.status(exception.apiCode().status()).headers(exception.getHeaders())
                .body(ApiResponse.failure(exception.apiCode(), List.of(), ServletApi.traceId()));
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException exception,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<FieldViolation> errors = exception.getBindingResult().getFieldErrors().stream()
                .map(error -> new FieldViolation(error.getField(), error.getCode(), error.getDefaultMessage()))
                .distinct().sorted(java.util.Comparator.comparing(FieldViolation::field).thenComparing(FieldViolation::code))
                .toList();
        return failure(CommonCode.VALIDATION_FAILED, errors);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ResponseEntity<Object> constraints(ConstraintViolationException exception) {
        return failure(CommonCode.VALIDATION_FAILED, exception.getConstraintViolations().stream()
                .map(error -> new FieldViolation(error.getPropertyPath().toString(),
                        error.getConstraintDescriptor().getAnnotation().annotationType().getSimpleName(), error.getMessage()))
                .toList());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<Object> conflict(DataIntegrityViolationException exception) {
        return failure(CommonCode.CONFLICT, List.of());
    }

    @ExceptionHandler({org.springframework.dao.DataAccessException.class,
            org.springframework.transaction.TransactionException.class})
    ResponseEntity<Object> dependencyUnavailable(Exception exception) {
        ApiLog.failure(CommonCode.SERVICE_UNAVAILABLE.name(), exception, ServletApi.traceId());
        return failure(CommonCode.SERVICE_UNAVAILABLE, List.of());
    }

    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    ResponseEntity<Object> denied(org.springframework.security.access.AccessDeniedException exception) {
        dev.kaidev.common.security.SecurityAudit.record(dev.kaidev.common.security.SecurityAudit.Event.ACCESS_DENIED,
                dev.kaidev.common.security.SecurityAudit.Outcome.DENIED, null, ServletApi.traceId());
        return failure(CommonCode.ACCESS_DENIED, List.of());
    }

    @ExceptionHandler(org.springframework.security.core.AuthenticationException.class)
    ResponseEntity<Object> unauthenticated(org.springframework.security.core.AuthenticationException exception) {
        return failure(CommonCode.UNAUTHENTICATED, List.of());
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception exception, Object body, HttpHeaders headers,
            HttpStatusCode status, WebRequest request) {
        ApiCode code = CommonCode.fromStatus(status.value());
        if (status.is5xxServerError()) ApiLog.failure(code.name(), exception, ServletApi.traceId());
        return new ResponseEntity<>(ApiResponse.failure(code, List.of(), ServletApi.traceId()), headers, status);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> unexpected(Exception exception) {
        ApiLog.failure(CommonCode.INTERNAL_ERROR.name(), exception, ServletApi.traceId());
        return failure(CommonCode.INTERNAL_ERROR, List.of());
    }

    private ResponseEntity<Object> failure(ApiCode code, List<FieldViolation> errors) {
        return ResponseEntity.status(code.status()).body(ApiResponse.failure(code, errors, ServletApi.traceId()));
    }
}
