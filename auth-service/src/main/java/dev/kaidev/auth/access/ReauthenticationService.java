package dev.kaidev.auth.access;

import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ReauthenticationService {
    private final ActorSecurity security;private final ReauthenticationProofs proofs;
    public ReauthenticationService(ActorSecurity security,ReauthenticationProofs proofs){this.security=security;this.proofs=proofs;}
    @Transactional public ReauthenticationProofs.Issued confirm(UUID owner,String password){
        // A new proof always requires the password, never another proof.
        if(password==null||password.isBlank())throw new dev.kaidev.common.exception.ApiException(dev.kaidev.common.api.code.CommonCode.INVALID_REQUEST);
        var user=security.lock(owner);security.reauthenticate(user,password);return proofs.issue(user);
    }
}
