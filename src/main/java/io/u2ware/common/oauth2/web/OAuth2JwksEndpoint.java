package io.u2ware.common.oauth2.web;

import com.nimbusds.jose.jwk.JWKSet;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public abstract class OAuth2JwksEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());
    protected OAuth2JwksEndpoint(){}
    
    @RequestMapping(value = "/oauth2/jwks", method = {RequestMethod.GET})
    public ResponseEntity<Object> oauth2jwks(HttpServletRequest request) {
        try {
            return ResponseEntity.ok(jwks());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    public abstract Object jwks() throws Exception;

    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2JwksEndpoint{
        private ResourceServer(){}
        private @Autowired(required = false) @Lazy JWKSet jwkSet;

        @Override
        public Object jwks() throws Exception {
            return jwkSet.toPublicJWKSet().toJSONObject();
        }
    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////  
    public static class ClientBroker extends OAuth2JwksEndpoint{
        private ClientBroker(){}
        private @Autowired(required = false) @Lazy JWKSet jwkSet;

        @Override
        public Object jwks() throws Exception {
            return jwkSet.toPublicJWKSet().toJSONObject();
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
        private OAuth2JwksEndpoint endpoint;
        private Builder(OAuth2JwksEndpoint endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2JwksEndpoint build(){
            return endpoint;
        }
    }
}
