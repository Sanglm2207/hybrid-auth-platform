package dev.kaidev.auth.access;

import dev.kaidev.auth.identity.DeviceRepository;
import dev.kaidev.auth.hardening.AuthAuditStore;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceTrust {
    private final dev.kaidev.auth.service.SessionService sessions;
    private final ActorSecurity security;private final DeviceRepository devices;private final AuthAuditStore audit;
    public DeviceTrust(ActorSecurity security,DeviceRepository devices,AuthAuditStore audit,dev.kaidev.auth.service.SessionService sessions){this.security=security;this.devices=devices;this.audit=audit;this.sessions=sessions;}
    @Transactional public void set(UUID owner,UUID device,int days,String password){
        var user=security.lock(owner);security.require(user,"devices:trust");security.reauthenticate(user,password);
        if(days<0||days>90)throw new ApiException(CommonCode.INVALID_REQUEST);
        var record=devices.findByUserIdAndDeviceId(owner,device).orElseThrow(()->new ApiException(CommonCode.NOT_FOUND));
        if(days==0)for(var session:sessions.list(owner,null))if(session.deviceId().equals(device))sessions.revokeSession(owner,session.id());
        record.trustExpiresAt=days==0?null:Instant.now().plusSeconds(days*86400L);
        audit.append(owner,SecurityAudit.Event.DEVICE_TRUST_CHANGED,Map.of("targetUserId",owner,"deviceId",device));
    }
}
