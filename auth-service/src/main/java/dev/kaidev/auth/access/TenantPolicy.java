package dev.kaidev.auth.access;

import dev.kaidev.auth.hardening.AuthAuditStore;
import dev.kaidev.auth.identity.IdentityValidationService;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantPolicy {
    public record TenantView(UUID id,String name,UUID ownerId) {}
    private final JdbcTemplate jdbc;private final ActorSecurity security;private final IdentityValidationService identities;private final AuthAuditStore audit;
    public TenantPolicy(JdbcTemplate jdbc,ActorSecurity security,IdentityValidationService identities,AuthAuditStore audit){this.jdbc=jdbc;this.security=security;this.identities=identities;this.audit=audit;}
    @Transactional public TenantView create(UUID actor,String name,String password){
        var user=security.lock(actor);security.require(user,"tenants:manage");security.reauthenticate(user,password);
        if(name==null||name.isBlank()||name.length()>100)throw new ApiException(CommonCode.INVALID_REQUEST);
        UUID id=UUID.randomUUID();jdbc.update("insert into identity_tenants(id,name,owner_id) values(?,?,?)",id,name,actor);
        jdbc.update("insert into identity_tenant_members(tenant_id,user_id) values(?,?)",id,actor);
        audit.append(actor,SecurityAudit.Event.TENANT_CHANGED,Map.of("targetUserId",actor));return new TenantView(id,name,actor);
    }
    public List<TenantView> list(UUID owner){return jdbc.query("select t.* from identity_tenants t join identity_tenant_members m on m.tenant_id=t.id where m.user_id=? order by t.name,t.id",
            (r,n)->new TenantView(r.getObject("id",UUID.class),r.getString("name"),r.getObject("owner_id",UUID.class)),owner);}
    @Transactional public void membership(UUID actor,UUID tenant,UUID target,boolean add,String password){
        var held=new HashMap<UUID,dev.kaidev.auth.entity.AppUser>();
        java.util.stream.Stream.of(actor,target).distinct().sorted().forEach(id->held.put(id,security.lock(id)));
        security.require(held.get(actor),"tenants:manage");security.reauthenticate(held.get(actor),password);
        var owners=jdbc.query("select owner_id from identity_tenants where id=? for update",(r,n)->r.getObject(1,UUID.class),tenant);
        if(owners.isEmpty()||!owners.getFirst().equals(actor))throw new ApiException(CommonCode.NOT_FOUND);
        if(!held.get(target).active||held.get(target).deletedAt!=null||held.get(target).adminLocked)throw new ApiException(CommonCode.NOT_FOUND);
        if(!add && target.equals(actor))throw new ApiException(CommonCode.CONFLICT);
        jdbc.update("delete from identity_tenant_members where tenant_id=? and user_id=?",tenant,target);
        if(add)jdbc.update("insert into identity_tenant_members(tenant_id,user_id) values(?,?)",tenant,target);
        audit.append(actor,SecurityAudit.Event.TENANT_CHANGED,Map.of("targetUserId",target));
    }
    @Transactional public void delete(UUID actor,UUID tenant,String password){
        var user=security.lock(actor);security.require(user,"tenants:manage");security.reauthenticate(user,password);
        if(jdbc.update("delete from identity_tenants where id=? and owner_id=?",tenant,actor)!=1)throw new ApiException(CommonCode.NOT_FOUND);
        audit.append(actor,SecurityAudit.Event.TENANT_CHANGED,Map.of("targetUserId",actor));
    }
    @Transactional public boolean profile(IdentityCheck identity,UUID target,UUID tenant,String action){
        if(!Set.of("read","update").contains(action))return false;
        var access=identities.check(identity);if(!access.active())return false;
        if(identity.subject().equals(target))return access.permissions().contains(action.equals("read")?"profile:read":"profile:write");
        if(tenant==null||!access.permissions().contains("users:"+action))return false;
        // Both memberships, account states and action grants come from SQL, never from tenant headers/JWT roles.
        return jdbc.queryForObject("select count(*) from identity_tenant_members m join app_users u on u.id=m.user_id where m.tenant_id=? and m.user_id in (?,?) and u.active=true and u.admin_locked=false and u.deleted_at is null",
                Long.class,tenant,identity.subject(),target)==2;
    }
}
