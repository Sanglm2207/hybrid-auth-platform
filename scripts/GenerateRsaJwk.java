import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

// Used by jwt-keys.py. Private output is captured in memory and never printed by the wrapper.
class GenerateRsaJwk {
    static String b64(BigInteger number) {
        byte[] bytes = number.toByteArray();
        if (bytes[0] == 0) bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    public static void main(String[] args) throws Exception {
        RSAPrivateCrtKey key;
        if (args.length == 2) {
            String pem = Files.readString(Path.of(args[1])).replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            key = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        } else {
            var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072);
            key = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();
        }
        var parts = new LinkedHashMap<String, String>();
        parts.put("kty", "RSA"); parts.put("use", "sig"); parts.put("alg", "RS256"); parts.put("kid", args[0]);
        parts.put("n", b64(key.getModulus())); parts.put("e", b64(key.getPublicExponent()));
        parts.put("d", b64(key.getPrivateExponent())); parts.put("p", b64(key.getPrimeP())); parts.put("q", b64(key.getPrimeQ()));
        parts.put("dp", b64(key.getPrimeExponentP())); parts.put("dq", b64(key.getPrimeExponentQ())); parts.put("qi", b64(key.getCrtCoefficient()));
        System.out.println("{" + String.join(",", parts.entrySet().stream().map(e -> "\""+e.getKey()+"\":\""+e.getValue()+"\"").toList()) + "}");
    }
}
