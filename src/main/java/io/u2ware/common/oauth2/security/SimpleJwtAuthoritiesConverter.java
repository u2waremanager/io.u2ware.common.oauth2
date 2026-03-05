package io.u2ware.common.oauth2.security;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public interface SimpleJwtAuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>>{


}
