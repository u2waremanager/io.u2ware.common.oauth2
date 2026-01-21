package io.u2ware.common.oauth2.jwt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class UserServiceManager implements UserDetailsService{

	protected Log logger = LogFactory.getLog(getClass());

    protected SecurityProperties sp;
    protected UserDetailsConverter converter;
    protected @Autowired(required = false) @Lazy PasswordEncoder passwordEncoder;


    public UserServiceManager(UserDetailsConverter converter, SecurityProperties sp){
        this.converter = converter;
        this.sp = sp;
    }
    public UserServiceManager(UserDetailsConverter converter){
        this.converter = converter;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        try{
            return this.converter.loadUserByUsername(username);
        }catch(Exception e){

        }



        String rootUser = this.sp.getUser().getName();
        if(! rootUser.equals(username)) {
            throw new UsernameNotFoundException("User not found: " + username);
        }        

        String password = this.sp.getUser().getPassword();
        String rootPassword = passwordEncoder != null ? passwordEncoder.encode(password) : "{noop}"+password;

        UserDetails userDetails = User.builder()
            .username(rootUser)
            .password(rootPassword)
            .roles("ADMIN")
            .build();
        return userDetails;
    }
    
}
