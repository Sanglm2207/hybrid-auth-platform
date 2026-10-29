package dev.kaidev.auth.hardening;

import jakarta.persistence.*;

@Entity @Table(name="identity_admin_guard")
public class AdminGuard { @Id public Integer id; }
