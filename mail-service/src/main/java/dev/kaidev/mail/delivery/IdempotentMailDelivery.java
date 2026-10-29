package dev.kaidev.mail.delivery;

import com.fasterxml.jackson.databind.*;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.mail.dto.SendMailRequest;
import dev.kaidev.mail.service.MailDeliveryService;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdempotentMailDelivery {
    private final DeliveryReceiptRepository receipts;private final MailDeliveryService sender;
    private final String fingerprintKey;
    private final ObjectMapper json=new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,true);
    public IdempotentMailDelivery(DeliveryReceiptRepository receipts,MailDeliveryService sender,dev.kaidev.mail.config.MailProperties properties){this.receipts=receipts;this.sender=sender;this.fingerprintKey=properties.apiKey();}
    @Transactional public void send(SendMailRequest request,UUID id){
        String hash;
        try{
            // A plain digest would allow offline guessing of six-digit OTPs from receipt rows.
            var mac=javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(fingerprintKey.getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
            hash=HexFormat.of().formatHex(mac.doFinal(json.writeValueAsBytes(request)));
        }catch(Exception e){throw new IllegalStateException("Unable to fingerprint delivery");}
        var receipt=receipts.lock(id).orElse(null);
        if(receipt!=null){if(!receipt.requestHash.equals(hash))throw new ApiException(CommonCode.CONFLICT);if(receipt.state.equals("SENT"))return;}
        else{receipt=new DeliveryReceipt();receipt.id=id;receipt.requestHash=hash;receipt.state="PENDING";receipt=receipts.saveAndFlush(receipt);}
        sender.send(request,id);receipt.state="SENT";receipt.sentAt=Instant.now();
    }
}
