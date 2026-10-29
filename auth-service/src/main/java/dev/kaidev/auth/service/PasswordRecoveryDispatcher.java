package dev.kaidev.auth.service;

import dev.kaidev.auth.outbox.AuthOutbox;
import org.springframework.stereotype.Component;

@Component
public class PasswordRecoveryDispatcher {
    private final AuthOutbox outbox;
    public PasswordRecoveryDispatcher(AuthOutbox outbox){this.outbox=outbox;}
    public void enqueue(String email){outbox.recovery(email);}
}
