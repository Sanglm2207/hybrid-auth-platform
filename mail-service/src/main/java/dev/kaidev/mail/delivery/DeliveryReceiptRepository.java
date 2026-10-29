package dev.kaidev.mail.delivery;
import jakarta.persistence.LockModeType;
import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
public interface DeliveryReceiptRepository extends JpaRepository<DeliveryReceipt,UUID>{
    @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select r from DeliveryReceipt r where r.id=:id") Optional<DeliveryReceipt> lock(@Param("id") UUID id);
}
