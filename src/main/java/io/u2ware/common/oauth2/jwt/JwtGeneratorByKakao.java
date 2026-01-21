package io.u2ware.common.oauth2.jwt;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.Map;

public class JwtGeneratorByKakao implements JwtGenerator{

    @Override
    @SuppressWarnings("unchecked")
    public void extractClaims(Map<String, Object> claims, Map<String, Object> principal, String registrationId) {


        Object sub = registrationId + "_" + principal.getOrDefault("id", "unknown");
        Object email = principal.getOrDefault("email", "");
        Object name = principal.getOrDefault("name", "");  


        Map<String, Object> kakaoAccount = (Map<String, Object>) principal.get("kakao_account");
        if(kakaoAccount != null) {
            email = kakaoAccount.getOrDefault("email", "");

            Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
            if (profile != null) {
                name = profile.getOrDefault("nickname", "");  
            }
        }



        claims.put(IdTokenClaimNames.SUB, sub);
        claims.put("email", email);
        claims.put("name", name);
        claims.put("provider", principal);
    }
}
