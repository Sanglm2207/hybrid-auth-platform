package dev.kaidev.auth.identity;

import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceRegistry {
    public record DeviceView(UUID id, String userAgent, String lastIp, Instant firstSeenAt, Instant lastActivityAt,
            int activeSessions, boolean current, boolean trusted, Instant trustExpiresAt) {
        @Override public String toString() { return "DeviceView[REDACTED]"; }
    }
    private final org.springframework.context.ApplicationEventPublisher events;
    private final DeviceRepository devices;
    public DeviceRegistry(DeviceRepository devices,org.springframework.context.ApplicationEventPublisher events,dev.kaidev.auth.repository.UserRepository users) { this.devices = devices;this.events=events;this.users=users; }
    @Transactional
    public void observe(UUID userId, DeviceInfo info) {
        // Caller holds the owning user row lock during login/refresh, serializing first registration.
        var existing = devices.findByUserIdAndDeviceId(userId, info.deviceId());
        var device = existing.orElseGet(() -> {
            var created = new AuthDevice(); created.userId = userId; created.deviceId = info.deviceId();
            created.firstSeenAt = Instant.now(); return created;
        });
        device.lastSeenAt = Instant.now(); device.lastIp = info.ip(); device.userAgent = info.userAgent(); devices.save(device);
        if(existing.isEmpty() && events!=null) events.publishEvent(new dev.kaidev.auth.service.AccountMailNotifications.Notice(userId,
                // Look up the recipient through the owning transaction, never a request-provided address.
                recipient(userId),"new-device-login",java.util.Map.of()));
    }
    private final dev.kaidev.auth.repository.UserRepository users;
    private String recipient(UUID id){return users.findById(id).orElseThrow().email;}
    @Transactional(readOnly = true)
    public List<DeviceView> list(UUID userId, List<SessionView> active) {
        return devices.findByUserIdOrderByLastSeenAtDesc(userId).stream().map(device -> {
            var sessions = active.stream().filter(s -> s.deviceId().equals(device.deviceId)).toList();
            Instant activity = sessions.stream().map(SessionView::lastActivityAt).max(Comparator.naturalOrder())
                    .filter(time -> time.isAfter(device.lastSeenAt)).orElse(device.lastSeenAt);
            return new DeviceView(device.deviceId, device.userAgent, device.lastIp, device.firstSeenAt, activity,
                    sessions.size(), sessions.stream().anyMatch(SessionView::current),device.trustExpiresAt!=null&&device.trustExpiresAt.isAfter(Instant.now()),device.trustExpiresAt);
        }).toList();
    }
}
