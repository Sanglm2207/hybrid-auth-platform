package dev.kaidev.auth.hardening;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.*;

public interface AdminGuardRepository extends JpaRepository<AdminGuard,Integer> {
    @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select g from AdminGuard g where g.id = 1") Optional<AdminGuard> lockGuard();
    @Query(value="select count(distinct u.id) from app_users u join identity_user_roles ur on ur.user_id=u.id join identity_role_permissions rp on rp.role_name=ur.role_name where u.active=true and u.email_verified=true and rp.permission='roles:manage'", nativeQuery=true)
    long activeManagers();
}
