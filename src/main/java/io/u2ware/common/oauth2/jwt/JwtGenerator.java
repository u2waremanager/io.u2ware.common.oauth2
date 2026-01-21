package io.u2ware.common.oauth2.jwt;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.*;

public interface JwtGenerator {
    Set<String> ID_TOKEN_CLAIMS = Set.of(
            IdTokenClaimNames.ISS,
            IdTokenClaimNames.SUB,
            IdTokenClaimNames.AUD,
            IdTokenClaimNames.EXP,
            IdTokenClaimNames.IAT,
            IdTokenClaimNames.AUTH_TIME,
            IdTokenClaimNames.NONCE,
            IdTokenClaimNames.ACR,
            IdTokenClaimNames.AMR,
            IdTokenClaimNames.AZP,
            IdTokenClaimNames.AT_HASH,
            IdTokenClaimNames.C_HASH
    );

    void extractClaims(Map<String, Object> claims, Map<String, Object> principal, String registrationId);
}
