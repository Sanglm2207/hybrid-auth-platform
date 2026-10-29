package dev.kaidev.auth.identity;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.servlet.support.VerifiedClientAddress;
import java.util.*;
import org.springframework.web.context.request.*;

public record DeviceInfo(UUID deviceId, String ip, String userAgent) {
    public static DeviceInfo current(String key, UUID existingDevice) {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes context))
            return new DeviceInfo(existingDevice == null ? UUID.randomUUID() : existingDevice, "unknown", "unknown");
        var request = context.getRequest();
        UUID id = existingDevice;
        if (id == null && request.getHeader("X-Device-Id") != null) {
            try {
                if (Collections.list(request.getHeaders("X-Device-Id")).size() != 1) throw new IllegalArgumentException();
                id = UUID.fromString(request.getHeader("X-Device-Id"));
            } catch (IllegalArgumentException e) { throw new ApiException(CommonCode.INVALID_REQUEST); }
        }
        String agent = Optional.ofNullable(request.getHeader("User-Agent")).orElse("unknown").replaceAll("[\\p{Cntrl}]", "");
        if (agent.length() > 256) agent = agent.substring(0, 256);
        String ip = VerifiedClientAddress.resolve(request, key);
        if (ip.length() > 64) ip = "unknown";
        return new DeviceInfo(id == null ? UUID.randomUUID() : id, ip, agent);
    }
    @Override public String toString() { return "DeviceInfo[REDACTED]"; }
}
