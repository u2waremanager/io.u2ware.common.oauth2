package io.u2ware.common.oauth2.web;



import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public abstract class OAuth2UserinfoEndpoints {

    protected final Log logger = LogFactory.getLog(getClass());

    protected OAuth2UserinfoEndpoints(){}


    @RequestMapping(value = "/oauth2/userinfo", method = {RequestMethod.GET})
    public @ResponseBody ResponseEntity<Object> oauth2UserInfo(HttpServletRequest request) {
        return null;
    }

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
        private @Value("${spring.application.name}") String applicationName;
    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ClientBroker extends OAuth2UserinfoEndpoints{


        private ClientBroker(){}
        private @Value("${spring.application.name}") String applicationName;
        private @Autowired(required = false) @Lazy UserDetailsService userDetailsService;
        private @Autowired(required = false) @Lazy JwtDecoder jwtDecoder;

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

