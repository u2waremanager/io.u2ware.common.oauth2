package io.u2ware.common.oauth2.security;

import java.util.Enumeration;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.io.Resource;
import org.springframework.util.ObjectUtils;

import jakarta.servlet.http.HttpServletRequest;

public class OAuth2ResourceServerSupport {

    private OAuth2ResourceServerSupport(){
    }


    public static boolean available(OAuth2ResourceServerProperties properties){
        Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
        String jwkSetUri = properties.getJwt().getJwkSetUri();
        if(! ObjectUtils.isEmpty(publicKeyLocation)) {
            return true;
        }
        if(! ObjectUtils.isEmpty(jwkSetUri)) {
            return true;
        }        
        return false;
    }    


    public static String extractHeaderToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        while (headers.hasMoreElements()) { // typically there is only one (most servers enforce that)
            String value = headers.nextElement();
            if ((value.toLowerCase().startsWith("Bearer".toLowerCase()))) {
                String authHeaderValue = value.substring("Bearer".length()).trim();
                return authHeaderValue;
            }
        }
        return null;
    }

}
