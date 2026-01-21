package io.u2ware.common.oauth2.jwt;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

public class SimpleJwtAuthenticationConverter extends JwtAuthenticationConverter { //implements Converter<Jwt, AbstractAuthenticationToken> {
    
    // private JwtAuthenticationConverter converter;

    public SimpleJwtAuthenticationConverter(){
        this(new SimpleJwtGrantedAuthoritiesConverter());
    }
    public SimpleJwtAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter){
        super();
        super.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
    }

    

    // @Override
    // public AbstractAuthenticationToken convert(Jwt jwt) {
    //     return super.convert(jwt);
    // }
}
