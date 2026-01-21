package io.u2ware.common.oauth2.jwt;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.Map;

public class JwtGeneratorByNaver implements JwtGenerator{
    @Override
    @SuppressWarnings("unchecked")
    public void extractClaims(Map<String, Object> claims, Map<String, Object> principal, String registrationId) {


        Object sub = registrationId + "_" + principal.getOrDefault("id", "unknown");
        Object email = principal.getOrDefault("email", "");
        Object name = principal.getOrDefault("name", "");  


        Map<String, Object> response = (Map<String, Object>) principal.get("response");
        if(response != null) {
            sub = registrationId + "_" + response.getOrDefault("id", "unknown");
            email = response.getOrDefault("email", "");
            name = response.getOrDefault("name", "");  
        }

        claims.put(IdTokenClaimNames.SUB, sub);
        claims.put("email", email);
        claims.put("name", name);
        claims.put("provider", principal);
    }
}
