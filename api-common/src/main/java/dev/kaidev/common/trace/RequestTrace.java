package dev.kaidev.common.trace;

import java.util.UUID;
import java.util.regex.Pattern;

public final class RequestTrace {
    public static final String HEADER = "X-Request-Id";
    public static final String ATTRIBUTE = RequestTrace.class.getName();
    private static final Pattern VALID = Pattern.compile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}");
    private RequestTrace() {}
    public static String resolve(String candidate) {
        return candidate != null && VALID.matcher(candidate).matches() ? candidate : UUID.randomUUID().toString();
    }
}
