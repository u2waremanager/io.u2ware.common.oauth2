package io.u2ware.common.oauth2.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jwt.JwtGenerators;
import jakarta.servlet.http.HttpServletRequest;

@Controller
public abstract class OAuth2LogonEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    protected OAuth2LogonEndpoint(){}


    @RequestMapping(value = "/oauth2/logon", method = {RequestMethod.GET, RequestMethod.POST})
    public @ResponseBody ResponseEntity<Object> oauth2Logon(HttpServletRequest request, Authentication authentication) {

        logger.info("OAuth2 Logon: " + authentication);
        logger.info("OAuth2 Logon: " + authentication.getClass());
        logger.info("OAuth2 Logon: " + authentication.getName());

        if (authentication == null || ! authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        MultiValueMap<String,String> parameters = parameters(request, authentication);
        String callback = callback(request, authentication);
        
        logger.info("OAuth2 Logon : " + parameters);
        logger.info("OAuth2 Logon : " + callback);

        if(StringUtils.hasText(callback)) {

            UriComponents redirectUri = UriComponentsBuilder
                    .fromUriString(callback)
                    .queryParams(parameters)
                    // .queryParam("username", principalName)
                    // .queryParam("raw_info", userinfo)
                    // .queryParam("raw_token", accessToken)
                    // .queryParam("token_type", tokenType)
                    // .queryParam("id_token", idToken)
                    .build();

            logger.info("OAuth2 Logon : " + callback);
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(redirectUri.toUri());
            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();


        }else{

            HttpHeaders headers = new HttpHeaders();
            headers.addAll(parameters);
            // headers.add("username", principalName);
            // headers.add("raw_info", userinfo);
            // headers.add("raw_token", accessToken);
            // headers.add("token_type", tokenType);
            // headers.add("id_token", idToken);
            return ResponseEntity.status(HttpStatus.OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .headers(headers)
                    .body(headers);

        }
    }

    protected abstract MultiValueMap<String,String> parameters(HttpServletRequest request, Authentication authentication);
    protected abstract String callback(HttpServletRequest request, Authentication authentication);
    


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ResourceServer extends OAuth2LogonEndpoint{

        private ResourceServer(){}
        private @Autowired(required = false) @Lazy JwtEncoder jwtEncoder;

        @Override
        protected MultiValueMap<String, String> parameters(HttpServletRequest request, Authentication authentication) {

            String principalName = authentication.getName();

            Jwt jwt = JoseKeyEncryptor.encrypt(jwtEncoder, (claims)-> { 
                claims.put("sub", principalName);
                claims.put("email", principalName);
                claims.put("name", principalName);
            });

            String accessToken = jwt.getTokenValue();
            String tokenType = "Bearer";
            String idToken = jwt.getTokenValue();
            String userinfo = ServletUriComponentsBuilder.fromContextPath(request)
                            .path("/oauth2/userinfo").build().toUriString();


            MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>();
            parameters.add("username", principalName);
            parameters.add("raw_info", userinfo);
            parameters.add("raw_token", accessToken);
            parameters.add("token_type", tokenType);
            parameters.add("id_token", idToken);
            return parameters;
        }
        @Override
        protected String callback(HttpServletRequest request, Authentication authentication) {
            Object value = WebUtils.getSessionAttribute(request, "callback");
            if(ObjectUtils.isEmpty(value)) return "";
            return value.toString();
        }

    }

    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    public static class ClientBroker extends OAuth2LogonEndpoint{

        private ClientBroker(){}

        private @Autowired(required = false) @Lazy ClientRegistrationRepository clientRegistrationRepository;
        private @Autowired(required = false) @Lazy AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
        private @Autowired(required = false) @Lazy OAuth2AuthorizedClientService authorizedClientService;
        private @Autowired(required = false) @Lazy JwtEncoder jwtEncoder;

        @Override
        protected MultiValueMap<String, String> parameters(HttpServletRequest request, Authentication authentication) {

            OAuth2AuthenticationToken oauth2AuthenticationToken = null;// from authentication

            String principalName = oauth2AuthenticationToken.getName();
            String clientRegistrationId = oauth2AuthenticationToken.getAuthorizedClientRegistrationId();
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId,
                    principalName);

            JwtGenerators jwtGenerator = JwtGenerators.of(clientRegistration.getRegistrationId());
            Jwt jwt = jwtGenerator.generate(jwtEncoder, oauth2AuthenticationToken);


            String userinfo = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();
            String tokenType = authorizedClient.getAccessToken().getTokenType().getValue();
            String accessToken = authorizedClient.getAccessToken().getTokenValue();
            String idToken = jwt.getTokenValue();
            logger.info("OAuth2 clientRegistration       : " + clientRegistration);
            logger.info("OAuth2 authorizedClient         : " + authorizedClient);
            logger.info("OAuth2 principalName            : " + principalName);
            logger.info("OAuth2 jwtGenerator             : " + jwtGenerator.name());
            logger.info("OAuth2 jwt                      : " + jwt.getClaims());


            MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>();
            parameters.add("username", principalName);
            parameters.add("raw_info", userinfo);
            parameters.add("raw_token", accessToken);
            parameters.add("token_type", tokenType);
            parameters.add("id_token", idToken);
            return parameters;
        }

        @Override
        protected String callback(HttpServletRequest request, Authentication authentication) {

            OAuth2AuthorizationRequest authorizationRequest = authorizationRequestRepository
                    .loadAuthorizationRequest(request);
            logger.info("OAuth2 authorizationRequest     : " + authorizationRequest);
            return authorizationRequest.getRedirectUri();

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
        private OAuth2LogonEndpoint endpoint;
        private Builder(OAuth2LogonEndpoint endpoint){
            this.endpoint = endpoint;
        }
        public OAuth2LogonEndpoint build(){
            return endpoint;
        }
    }
}
