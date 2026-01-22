package io.u2ware.common.oauth2.web;

import java.net.URI;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.WebUtils;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public abstract class OAuth2LoginEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    protected OAuth2LoginEndpoint(){}

    @RequestMapping(value = "/oauth2/login", method = {RequestMethod.GET}, params = {"provider", "callback"})
    public @ResponseBody ResponseEntity<Object> oauth2Login(HttpServletRequest request,
            @RequestParam("provider") String provider,
            @RequestParam("callback") String callback) {

        URI authorization = uri(request, provider, callback);
        if(authorization == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

        logger.info("\t[/oauth2/login]: "+authorization);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(authorization);
        return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();
    }


    protected abstract URI uri(HttpServletRequest request, String provider, String callback);


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2LoginEndpoint{

        private ResourceServer(){}
        private @Value("${spring.application.name}") String applicationName;

        @Override
        protected URI uri(HttpServletRequest request, String provider, String callback) {
            if(! provider.equals(applicationName)) return null;
            UriComponents authorization = ServletUriComponentsBuilder.fromContextPath(request)
                    .path("/login")
                    .build();
            WebUtils.setSessionAttribute(request, "callback", callback);

            return authorization.toUri();
        }
    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////  
    public static class ClientBroker extends ResourceServer{

        private ClientBroker(){}
        private @Value("${spring.application.name}") String applicationName;
        
        @Override
        protected URI uri(HttpServletRequest request, String provider, String callback) {

            if(provider.equals(applicationName)) {
                return super.uri(request, provider, callback);
            }

            UriComponents authorization = ServletUriComponentsBuilder.fromCurrentContextPath()
                    .path("/oauth2/authorization")
                    .pathSegment(provider)
                    .queryParam("callback", callback)
                    .build();

            return authorization.toUri();
        }
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
        private OAuth2LoginEndpoint endpoint;
        private Builder(OAuth2LoginEndpoint endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2LoginEndpoint build(){
            return endpoint;
        }
    }
}