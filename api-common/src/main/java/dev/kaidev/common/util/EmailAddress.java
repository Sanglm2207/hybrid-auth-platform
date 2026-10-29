package dev.kaidev.common.util;
import java.util.Locale;
public final class EmailAddress {
    private EmailAddress() {}
    public static String normalize(String email) { return email == null ? null : email.strip().toLowerCase(Locale.ROOT); }
}
