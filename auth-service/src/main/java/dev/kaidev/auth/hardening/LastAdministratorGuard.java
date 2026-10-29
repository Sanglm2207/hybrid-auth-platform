package dev.kaidev.auth.hardening;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.exception.ApiException;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;

@Component
public class LastAdministratorGuard {
    private final AdminGuardRepository guard; private final EntityManager entities;
    public LastAdministratorGuard(AdminGuardRepository guard, EntityManager entities) { this.guard=guard; this.entities=entities; }
    public long acquire() { guard.lockGuard().orElseThrow(); return guard.activeManagers(); }
    public void verify(long before) { entities.flush(); if(before>0 && guard.activeManagers()==0) throw new ApiException(AuthCode.LAST_ADMINISTRATOR); }
}
