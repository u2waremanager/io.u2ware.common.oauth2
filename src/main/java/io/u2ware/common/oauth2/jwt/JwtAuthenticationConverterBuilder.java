package io.u2ware.common.oauth2.jwt;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

public class JwtAuthenticationConverterBuilder extends JwtAuthenticationConverter{
    
    public JwtAuthenticationConverter build(Converter<Jwt, Collection<GrantedAuthority>> customJwtGrantedAuthoritiesConverter){

        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = null;
        if(customJwtGrantedAuthoritiesConverter == null) {
            JwtGrantedAuthoritiesConverter c = new JwtGrantedAuthoritiesConverter();
            c.setAuthoritiesClaimName("authorities");
            c.setAuthorityPrefix("");
            jwtGrantedAuthoritiesConverter = c;
        }else{
            jwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
        }

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;

    }

    private JwtAuthenticationConverterBuilder(){
        
    }

    private static JwtAuthenticationConverterBuilder instance;

    public static JwtAuthenticationConverterBuilder getInstance(){
        if(instance == null) {
            instance = new JwtAuthenticationConverterBuilder();
        }
        return instance;
    }
}