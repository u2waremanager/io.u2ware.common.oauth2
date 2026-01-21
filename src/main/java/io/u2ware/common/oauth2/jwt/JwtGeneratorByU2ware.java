package io.u2ware.common.oauth2.jwt;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

public class JwtGeneratorByU2ware implements JwtGenerator{
    
    protected Log logger = LogFactory.getLog(getClass());

    @Override
    // @SuppressWarnings("unchecked")
    public void extractClaims(Map<String, Object> claims, Map<String, Object> principal, String registrationId) {
        // logger.info(claims);
        // logger.info(principal);
        // logger.info(registrationId);
        Object sub = registrationId + "_" + principal.getOrDefault("sub", "unknown");
        Object name = principal.getOrDefault("name", "");
        Object email = principal.getOrDefault("sub", "");

        claims.put(IdTokenClaimNames.SUB, sub);
        claims.put("name", name);
        claims.put("email", email);
        claims.put("provider", principal);
    }

}
