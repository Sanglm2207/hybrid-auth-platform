package dev.kaidev.auth.identity;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleDefinition, String> {}
