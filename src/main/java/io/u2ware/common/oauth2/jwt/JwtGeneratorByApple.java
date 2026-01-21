package io.u2ware.common.oauth2.jwt;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.Map;

public class JwtGeneratorByApple implements JwtGenerator{

    @Override
    public void extractClaims(Map<String, Object> claims, Map<String, Object> principal, String registrationId) {

        Object sub = registrationId + "_" + principal.getOrDefault("sub", "unknown");
        Object email = principal.getOrDefault("email", "");
        Object name = principal.getOrDefault("name", "");


        claims.put(IdTokenClaimNames.SUB, sub);
        claims.put("email", email);
        claims.put("name", name);
        claims.put("provider", principal);

    }
}
