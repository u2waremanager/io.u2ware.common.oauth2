package io.u2ware.common.oauth2.web;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
public class OAuth2ProvidersEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    private @Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository;


    @RequestMapping(value = "/oauth2/providers", method = {RequestMethod.GET})
    public @ResponseBody List<Map<String,String>> oauth2Providers(HttpServletRequest request) {

        List<Map<String,String>> clients = new ArrayList<>();
            @SuppressWarnings("unchecked")
            Iterable<ClientRegistration> clientRegistrations = (Iterable<ClientRegistration>)clientRegistrationRepository;
            clientRegistrations.forEach(clientRegistration->{
                String clientRegistrationId = clientRegistration.getRegistrationId();
                String clientName = clientRegistration.getClientName();

                Map<String,String> client = provider(request, clientRegistrationId, clientName);     
                clients.add(client);
            });
        logger.info("\t[/oauth2/providers]: "+clients);
        
        return clients;            
    }


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


}
