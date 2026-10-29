package dev.kaidev.mail.constant;

import dev.kaidev.common.api.code.ApiCode;
import org.springframework.http.HttpStatus;

public enum MailCode implements ApiCode {
    MAIL_SENT(HttpStatus.OK, "Email accepted by the SMTP provider"),
    MAIL_NOT_CONFIGURED(HttpStatus.SERVICE_UNAVAILABLE, "Mail delivery is not configured"),
    MAIL_DELIVERY_FAILED(HttpStatus.SERVICE_UNAVAILABLE, "Unable to send email. Try again later"),
    TEMPLATE_NOT_FOUND(HttpStatus.NOT_FOUND, "Email template does not exist"),
    TEMPLATE_VARIABLES_INVALID(HttpStatus.BAD_REQUEST, "Provide exactly the variables required by the template");

    private final HttpStatus status;
    private final String message;
    MailCode(HttpStatus status, String message) { this.status = status; this.message = message; }
    public HttpStatus status() { return status; }
    public String message() { return message; }
}
