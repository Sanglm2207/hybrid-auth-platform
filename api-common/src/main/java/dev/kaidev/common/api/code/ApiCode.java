package dev.kaidev.common.api.code;

import org.springframework.http.HttpStatus;

public interface ApiCode {
    String name();
    String message();
    HttpStatus status();
}
