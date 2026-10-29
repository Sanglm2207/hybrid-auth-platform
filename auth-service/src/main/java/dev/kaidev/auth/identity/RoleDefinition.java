package dev.kaidev.auth.identity;

import jakarta.persistence.*;
import java.util.*;

@Entity
@Table(name = "identity_roles")
public class RoleDefinition {
    @Id @Column(length = 32) public String name;
    @ElementCollection
    @CollectionTable(name = "identity_role_permissions", joinColumns = @JoinColumn(name = "role_name"))
    @Column(name = "permission", length = 64, nullable = false)
    public Set<String> permissions = new HashSet<>();
    protected RoleDefinition() {}
    public RoleDefinition(String name, Set<String> permissions) { this.name = name; this.permissions = new HashSet<>(permissions); }
}
