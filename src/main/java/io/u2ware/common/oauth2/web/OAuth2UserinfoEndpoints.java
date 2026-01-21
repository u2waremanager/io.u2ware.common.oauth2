package io.u2ware.common.oauth2.web;


import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import jakarta.servlet.http.HttpServletRequest;

@Controller
public abstract class OAuth2UserinfoEndpoints {

    protected final Log logger = LogFactory.getLog(getClass());

    protected OAuth2UserinfoEndpoints(){}


    @RequestMapping(value = "/oauth2/userinfo", method = {RequestMethod.GET})
    public @ResponseBody ResponseEntity<Object> oauth2UserInfo(HttpServletRequest request) {

        String token = extractHeaderToken(request);
        Jwt jwt = null;
        try{
            jwt = jwt(token);
        }catch(Exception e){
            logger.info("oauth2UserInfo: "+token, e);
            return ResponseEntity.status(HttpStatusCode.valueOf(401)).build();
        }

        try{
            UserDetails user = userDetails(jwt);
            return ResponseEntity.ok(user);

        }catch(Exception e){
            return ResponseEntity.ok(jwt);
        }
    }

    protected abstract Jwt jwt(String token)throws Exception;
    protected abstract UserDetails userDetails(Jwt token)throws Exception;


    protected String extractHeaderToken(HttpServletRequest request) {
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


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2UserinfoEndpoints{
        private ResourceServer(){}
        private @Autowired(required = false) @Lazy JwtDecoder jwtDecoder;
        private @Autowired(required = false) @Lazy UserDetailsService userDetailsService;

        @Override
        protected Jwt jwt(String token) throws Exception{
            return JoseKeyEncryptor.decrypt(jwtDecoder, () -> token);
        }

        @Override
        protected UserDetails userDetails(Jwt token) throws Exception {
            return userDetailsService.loadUserByUsername(token.getSubject());
        }
    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ClientBroker extends ResourceServer{

    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////    
    public static Builder resourceServer(){
        return new Builder(new ResourceServer());
    }

    public static Builder clientBroker(){
        return new Builder(new ClientBroker());
    }

    public static class Builder {
        private OAuth2UserinfoEndpoints endpoint;
        private Builder(OAuth2UserinfoEndpoints endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2UserinfoEndpoints build(){
            return endpoint;
        }
    }
}

