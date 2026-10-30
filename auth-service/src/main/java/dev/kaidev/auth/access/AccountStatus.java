package dev.kaidev.auth.access;

public enum AccountStatus {
    ENABLED, DISABLED, SUSPENDED;
    public boolean active() { return this != DISABLED; }
    public boolean locked() { return this == SUSPENDED; }
    public static AccountStatus of(boolean active, boolean locked) {
        return !active ? DISABLED : locked ? SUSPENDED : ENABLED;
    }
}
