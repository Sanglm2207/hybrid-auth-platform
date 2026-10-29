package dev.kaidev.auth.identity;

import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceRegistry {
    public record DeviceView(UUID id, String userAgent, String lastIp, Instant firstSeenAt, Instant lastActivityAt,
            int activeSessions, boolean current) {
        @Override public String toString() { return "DeviceView[REDACTED]"; }
    }
    private final DeviceRepository devices;
    public DeviceRegistry(DeviceRepository devices) { this.devices = devices; }
    @Transactional
    public void observe(UUID userId, DeviceInfo info) {
        // Caller holds the owning user row lock during login/refresh, serializing first registration.
        var device = devices.findByUserIdAndDeviceId(userId, info.deviceId()).orElseGet(() -> {
            var created = new AuthDevice(); created.userId = userId; created.deviceId = info.deviceId();
            created.firstSeenAt = Instant.now(); return created;
        });
        device.lastSeenAt = Instant.now(); device.lastIp = info.ip(); device.userAgent = info.userAgent(); devices.save(device);
    }
    @Transactional(readOnly = true)
    public List<DeviceView> list(UUID userId, List<SessionView> active) {
        return devices.findByUserIdOrderByLastSeenAtDesc(userId).stream().map(device -> {
            var sessions = active.stream().filter(s -> s.deviceId().equals(device.deviceId)).toList();
            Instant activity = sessions.stream().map(SessionView::lastActivityAt).max(Comparator.naturalOrder())
                    .filter(time -> time.isAfter(device.lastSeenAt)).orElse(device.lastSeenAt);
            return new DeviceView(device.deviceId, device.userAgent, device.lastIp, device.firstSeenAt, activity,
                    sessions.size(), sessions.stream().anyMatch(SessionView::current));
        }).toList();
    }
}
