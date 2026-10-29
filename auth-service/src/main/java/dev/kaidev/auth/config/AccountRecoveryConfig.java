package dev.kaidev.auth.config;

import java.util.Map;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
public class AccountRecoveryConfig {
    @Bean
    ThreadPoolTaskExecutor passwordRecoveryExecutor(@Value("${app.account.recovery-workers:2}") int workers,
            @Value("${app.account.recovery-queue-capacity:100}") int capacity) {
        if (workers < 1 || workers > 16 || capacity < 1 || capacity > 1000)
            throw new IllegalArgumentException("Invalid password recovery executor configuration");
        var executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(workers); executor.setMaxPoolSize(workers); executor.setQueueCapacity(capacity);
        executor.setThreadNamePrefix("account-recovery-");
        executor.setWaitForTasksToCompleteOnShutdown(true); executor.setAwaitTerminationSeconds(20);
        executor.setTaskDecorator(task -> {
            Map<String, String> captured = MDC.getCopyOfContextMap();
            return () -> {
                Map<String, String> previous = MDC.getCopyOfContextMap();
                try { if (captured == null) MDC.clear(); else MDC.setContextMap(captured); task.run(); }
                finally { if (previous == null) MDC.clear(); else MDC.setContextMap(previous); }
            };
        });
        return executor;
    }
}
