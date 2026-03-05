package io.u2ware.common.oauth2.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import io.u2ware.common.oauth2.jwt.JwtClaims;

public interface SimpleJwtAuthenticationMapper {

    Map<String, Object> map(JwtAuthenticationToken token) ;



    public static class Default implements SimpleJwtAuthenticationMapper{

        @Override
        public Map<String, Object> map(JwtAuthenticationToken origin) {

            Jwt jwt = origin.getToken();
            String subject = jwt.getSubject();
            String username = jwt.getClaimAsString(JwtClaims.provider_user.name());
            List<String> authorities = origin.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());


            Map<String, Object> info = new HashMap<>();
            info.put("subject", subject);
            info.put("username", username);
            info.put("authorities", authorities);
            info.put("origin", origin);

            return info;
        }
    }

}
