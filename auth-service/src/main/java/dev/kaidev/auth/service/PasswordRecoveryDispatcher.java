package dev.kaidev.auth.service;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class PasswordRecoveryDispatcher {
    private final Executor executor;
    private final AccountLifecycleService accounts;
    public PasswordRecoveryDispatcher(@Qualifier("passwordRecoveryExecutor") Executor executor, AccountLifecycleService accounts) {
        this.executor = executor; this.accounts = accounts;
    }
    public void enqueue(String email) {
        try {
            // No user lookup on the HTTP thread: SMTP/account existence cannot change its response timing.
            executor.execute(() -> {
                try { accounts.forgotPassword(email); }
                catch (RuntimeException e) {
                    SecurityAudit.record(SecurityAudit.Event.ACCOUNT_RECOVERY_FAILURE, SecurityAudit.Outcome.FAILURE,
                            null, MDC.get("traceId"));
                }
            });
        } catch (RejectedExecutionException e) { throw new ApiException(CommonCode.SERVICE_UNAVAILABLE); }
    }
}
