package io.u2ware.common.oauth2.web;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public abstract class OAuth2ProvidersEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());
    protected OAuth2ProvidersEndpoint(){}

    @RequestMapping(value = "/oauth2/providers", method = {RequestMethod.GET})
    public @ResponseBody List<Map<String,String>> oauth2Providers(HttpServletRequest request) {

        List<Map<String,String>> clients = new ArrayList<>();
        providers(request, clients);
        logger.info("\t[/oauth2/providers]: "+clients);
        
        return clients;            
    }

    protected abstract void providers(HttpServletRequest request, List<Map<String,String>> clients);

    protected Map<String,String> provider(HttpServletRequest request, String clientRegistrationId, String clientName){
        UriComponents uri = ServletUriComponentsBuilder.fromContextPath(request)
                .path("/oauth2/login")
                .queryParam("provider", clientRegistrationId)
                .queryParam("callback", "")
                .build();

        Map<String,String> client = new HashMap<>();
        client.put("name", clientName);
        client.put("uri", uri.toString());
        return client;
    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2ProvidersEndpoint{

        private ResourceServer(){}
        private @Value("${spring.application.name}") String applicationName;

        @Override
        protected void providers(HttpServletRequest request, List<Map<String, String>> clients) {
            Map<String,String> client = provider(request, applicationName, applicationName);           
            clients.add(client);
        }
    }


    ///////////////////////////////////////
    //
    ///////////////////////////////////////   
    public static class ClientBroker extends ResourceServer{

        private ClientBroker(){}
        private @Value("${spring.application.name}") String applicationName;
        private @Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository;

        @Override @SuppressWarnings("unchecked")
        protected void providers(HttpServletRequest request, List<Map<String, String>> clients) {

            Iterable<ClientRegistration> clientRegistrations = (Iterable<ClientRegistration>)clientRegistrationRepository;
            clientRegistrations.forEach(clientRegistration->{
                String clientRegistrationId = clientRegistration.getRegistrationId();
                String clientName = clientRegistration.getClientName();

                if(! "dummy".equals(clientRegistrationId)) {
                    Map<String,String> client = provider(request, clientRegistrationId, clientName);         
                    clients.add(client);
                }
            });

            super.providers(request, clients);
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
        private OAuth2ProvidersEndpoint endpoint;
        private Builder(OAuth2ProvidersEndpoint endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2ProvidersEndpoint build(){
            return endpoint;
        }
    }


}
