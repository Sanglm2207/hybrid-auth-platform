package dev.kaidev.common.servlet.controller;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class ServletFallbackErrorController implements ErrorController {
    @RequestMapping("/error")
    ResponseEntity<?> error(HttpServletRequest request) {
        Object raw = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int status = raw instanceof Integer value ? value : 500;
        return ResponseEntity.status(status).body(ApiResponse.failure(CommonCode.fromStatus(status), List.of(), ServletApi.traceId(request)));
    }
}
