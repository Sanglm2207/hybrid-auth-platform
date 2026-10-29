package dev.kaidev.auth.identity;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RolePolicyService {
    public record RoleView(String name, Set<String> permissions) {}
    private final RoleRepository roles;
    public RolePolicyService(RoleRepository roles) { this.roles = roles; }
    @Transactional(readOnly = true)
    public Set<String> permissions(Set<String> assigned) {
        Set<String> result = new TreeSet<>();
        roles.findAllById(assigned).forEach(role -> result.addAll(role.permissions)); return Set.copyOf(result);
    }
    @Transactional(readOnly = true)
    public List<RoleView> list() {
        return roles.findAll().stream().map(r -> new RoleView(r.name, Set.copyOf(r.permissions)))
                .sorted(Comparator.comparing(RoleView::name)).toList();
    }
}
