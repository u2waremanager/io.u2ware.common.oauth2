package io.u2ware.common.oauth2.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import jakarta.servlet.http.HttpServletRequest;


@Controller
public abstract class OAuth2LogoutEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    protected OAuth2LogoutEndpoint(){}


    @RequestMapping(value = "/oauth2/logout", method = {RequestMethod.GET})
    public @ResponseBody ResponseEntity<Object> oauth2Logout(HttpServletRequest request){
        UriComponents logout = ServletUriComponentsBuilder.fromContextPath(request)
                .path("/logout")
                .build();
        logger.info("\t[/oauth2/logout]: "+logout);

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(logout.toUri());
        return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();
    }


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2LogoutEndpoint{
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
        private OAuth2LogoutEndpoint endpoint;
        private Builder(OAuth2LogoutEndpoint endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2LogoutEndpoint build(){
            return endpoint;
        }
    }

}
