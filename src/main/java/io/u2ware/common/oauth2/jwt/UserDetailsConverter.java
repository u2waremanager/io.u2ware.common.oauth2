package io.u2ware.common.oauth2.jwt;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsConverter {
    

   UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;


}
