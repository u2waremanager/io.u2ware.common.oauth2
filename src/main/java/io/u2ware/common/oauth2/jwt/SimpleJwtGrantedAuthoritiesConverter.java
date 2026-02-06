package io.u2ware.common.oauth2.jwt;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

public class SimpleJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>>{
    
    private JwtGrantedAuthoritiesConverter converter;
    public SimpleJwtGrantedAuthoritiesConverter(){
        this.converter = new JwtGrantedAuthoritiesConverter();
        this.converter.setAuthoritiesClaimName("authorities");
        this.converter.setAuthorityPrefix("");    
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
       return converter.convert(jwt);
    }


    private static SimpleJwtGrantedAuthoritiesConverter c = new SimpleJwtGrantedAuthoritiesConverter();

    public static Collection<GrantedAuthority> authorities(Jwt jwt){
        return c.convert(jwt);
    }

}