package dev.kaidev.gateway.config;

import java.net.InetAddress;
import java.util.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;

/** Only explicitly configured numeric proxy addresses may supply X-Forwarded-For. */
public final class TrustedIngressTransformer extends ForwardedHeaderTransformer {
    public static final String RESOLVED="X-Gateway-Resolved-Client";
    private final Set<String> trusted;
    public TrustedIngressTransformer(String proxies) {
        setRemoveOnly(true);
        var values=new HashSet<String>();
        for(String proxy:proxies.split(",")) if(!proxy.isBlank()) values.add(numeric(proxy.trim()));
        trusted=Set.copyOf(values);
    }
    static String numeric(String value) {
        if(value==null || value.length()>64 || !value.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("Numeric proxy IP required");
        if(!value.contains(":")) {
            String[] parts=value.split("\\.",-1);
            if(parts.length!=4)throw new IllegalArgumentException("IPv4 requires four decimal octets");
            for(String part:parts)if(!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part)>255)throw new IllegalArgumentException("Invalid IPv4 octet");
        }
        try{return InetAddress.getByName(value).getHostAddress();}catch(Exception e){throw new IllegalArgumentException("Invalid proxy IP");}
    }
    @Override public ServerHttpRequest apply(ServerHttpRequest request) {
        String resolved=request.getRemoteAddress()==null?null:request.getRemoteAddress().getAddress().getHostAddress();
        if(resolved!=null && trusted.contains(resolved)) {
            var lines=request.getHeaders().get("X-Forwarded-For");
            String raw=lines==null?"":String.join(",",lines);
            if(raw.length()<=2048 && !raw.isBlank()) {
                String[] hops=raw.split(",",-1);
                try {
                    if(hops.length>32) throw new IllegalArgumentException();
                    for(int i=hops.length-1;i>=0 && trusted.contains(resolved);i--) resolved=numeric(hops[i].trim());
                } catch(IllegalArgumentException e) { resolved=request.getRemoteAddress().getAddress().getHostAddress(); }
            }
        }
        String client=resolved;
        return super.apply(request).mutate().headers(h->{h.remove(RESOLVED);if(client!=null)h.set(RESOLVED,client);}).build();
    }
}
