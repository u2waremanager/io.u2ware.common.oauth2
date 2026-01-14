package io.u2ware.common.oauth2.jwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public interface OAuth2ResourceServerUserinfoService {
    
   UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}
