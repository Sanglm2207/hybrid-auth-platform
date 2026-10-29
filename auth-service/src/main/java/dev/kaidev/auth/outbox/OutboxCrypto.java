package dev.kaidev.auth.outbox;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class OutboxCrypto {
    private final byte[] key; private final SecureRandom random=new SecureRandom();
    public OutboxCrypto(@Value("${app.outbox.encryption-key:}") String key){
        if(!key.matches("[0-9a-fA-F]{64}"))throw new IllegalArgumentException("Configure a 32-byte hex outbox encryption key");
        this.key=HexFormat.of().parseHex(key);
    }
    public String encrypt(String aad,String value){try{
        byte[] iv=new byte[12];random.nextBytes(iv);var cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        byte[] data=cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));byte[] result=new byte[iv.length+data.length];System.arraycopy(iv,0,result,0,iv.length);System.arraycopy(data,0,result,iv.length,data.length);
        return Base64.getEncoder().encodeToString(result);
    }catch(Exception e){throw new IllegalStateException("Outbox encryption failed");}}
    public String decrypt(String aad,String value){try{
        byte[] data=Base64.getDecoder().decode(value);var cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,Arrays.copyOf(data,12)));cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(Arrays.copyOfRange(data,12,data.length)),StandardCharsets.UTF_8);
    }catch(Exception e){throw new IllegalStateException("Outbox decryption failed");}}
}
