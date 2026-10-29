package dev.kaidev.mail.delivery;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
@Entity @Table(name="mail_delivery_receipts")
public class DeliveryReceipt {
    @Id public UUID id;
    @Column(nullable=false,length=64) public String requestHash;
    @Column(nullable=false,length=16) public String state;
    public Instant sentAt;
}
