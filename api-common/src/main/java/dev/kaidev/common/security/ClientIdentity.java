package dev.kaidev.common.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Gateway-to-Auth identity proof; never trust arbitrary forwarded IP headers. */
public final class ClientIdentity {
    public static final String IP = "X-Auth-Client-IP";
    public static final String TIME = "X-Auth-Client-Time";
    public static final String SIGNATURE = "X-Auth-Client-Signature";
    private ClientIdentity() {}

    public static String sign(String key, String ip, String time, String method, String path) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((ip + "\n" + time + "\n" + method + "\n" + path)
                    .getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException("HMAC unavailable", e); }
    }

    public static boolean verify(String key, String ip, String time, String signature, String method, String path) {
        if (key == null || key.length() < 32 || ip == null || !ip.matches("[0-9a-fA-F:.%]{2,64}")
                || time == null || signature == null || !signature.matches("[0-9a-f]{64}")) return false;
        try {
            long seconds = Long.parseLong(time);
            long now = Instant.now().getEpochSecond();
            if (seconds < now - 30 || seconds > now + 5) return false;
            return MessageDigest.isEqual(sign(key, ip, time, method, path).getBytes(StandardCharsets.US_ASCII),
                    signature.getBytes(StandardCharsets.US_ASCII));
        } catch (NumberFormatException e) { return false; }
    }

    public static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
