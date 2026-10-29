package dev.kaidev.auth.hardening;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.exception.ApiException;
public class RefreshReuseException extends ApiException { public RefreshReuseException(){super(AuthCode.INVALID_REFRESH_TOKEN);} }
