package io.u2ware.common.oauth2.jwt;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

public class AuthenticationContext {


    private static JwtGrantedAuthoritiesConverter converter;
    private static JwtGrantedAuthoritiesConverter authoritiesConverter() {
        if(converter == null) {
            converter = new JwtGrantedAuthoritiesConverter();
            converter.setAuthoritiesClaimName("authorities");
            converter.setAuthorityPrefix("");
        } 
        return converter;
    }

    private AuthenticationContext(){}

    public static Jwt authenticationToken(Principal authentication) {
        if(authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            return jwtAuthenticationToken.getToken();
        } 
        return null;
    }


    @SuppressWarnings("unchecked")
    public static Collection<GrantedAuthority> authorities(Authentication authentication) {
        if(authentication == null) return Collections.EMPTY_LIST;
        return (Collection<GrantedAuthority>) authentication.getAuthorities();
    }
    @SuppressWarnings("unchecked")
    public static Collection<GrantedAuthority> authorities(Jwt jwt) {
        if(jwt == null) return Collections.EMPTY_LIST;
        return authoritiesConverter().convert(jwt);
    }




    /////////////////////////////////////////////////////////////////////
    /// 
    /////////////////////////////////////////////////////////////////////
    public static HttpServletRequest httpServletRequest() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        ServletRequestAttributes request = (ServletRequestAttributes)attrs;
        return request.getRequest();
    }


    public static Boolean isAnonymousUser(){
        try{
            // return ! "anonymousUser".equals(AuthenticationContext.authentication().getName());
            return (AuthenticationContext.authentication() instanceof AnonymousAuthenticationToken);
        }catch(Exception e){
            return false;
        }
    }    


    public static Authentication authentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static Jwt authenticationToken() {
        return authenticationToken(authentication());
    }

    public static Collection<GrantedAuthority> authorities() {
        HashSet<GrantedAuthority> authorities = new HashSet<>();
        authorities.addAll(authorities(authentication()));
        authorities.addAll(authorities(authenticationToken()));
        return authorities;
    }

    public static boolean hasAuthorities(String... roles) {

        Collection<GrantedAuthority> authorities = authorities();
        if(roles.length < 1 || authorities.size() < 1) return false;

        boolean result = true;
        for(String role : roles) {
            if(StringUtils.hasLength(role)) {
                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
                result = result && authorities.contains(authority);    
            }else{
                result = result && false;
            }
        }
        return result; 
    }
}
