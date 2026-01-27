package io.u2ware.common.oauth2.web;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

import io.u2ware.common.oauth2.jwt.JwtGenerators;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class OAuth2LogonEndpoint implements AuthenticationSuccessHandler {

    protected final Log logger = LogFactory.getLog(getClass());

    private @Autowired(required = false) @Lazy ClientRegistrationRepository clientRegistrationRepository;
    private @Autowired(required = false) @Lazy AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    private @Autowired(required = false) @Lazy OAuth2AuthorizedClientService authorizedClientService;
    private @Autowired(required = false) @Lazy JwtEncoder jwtEncoder;


    @RequestMapping(value = "/oauth2/logon", method = {RequestMethod.GET})
    public @ResponseBody ResponseEntity<Object> oauth2Logon(HttpServletRequest request, Authentication authentication) {


        MultiValueMap<String,String> parameters = parameters(request, authentication);
        logger.info("\t[/oauth2/logon]: "+parameters);
        String callback = callback(request, authentication);
        logger.info("\t[/oauth2/logon]: "+callback);


        if(StringUtils.hasText(callback)) {

            UriComponents redirectUri = UriComponentsBuilder
                    .fromUriString(callback)
                    .queryParams(parameters)
                    .build();


            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(redirectUri.toUri());
            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();

        }else{

            HttpHeaders headers = new HttpHeaders();
            headers.addAll(parameters);

            return ResponseEntity.status(HttpStatus.OK)
                    .contentType(MediaType.APPLICATION_JSON)
                    .headers(headers)
                    .body(headers);
        }
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {


                								System.err.println("=================================");
								System.err.println("");
								System.err.println(authentication.getClass());
								System.err.println(authentication.getPrincipal().getClass());
								System.err.println("");
								System.err.println("=================================");

    }



    protected MultiValueMap<String, String> parameters(HttpServletRequest request, Authentication authentication) {

        OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;// from
                                                                                                         // authentication

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
        String name = jwt.getClaimAsString("name");

        // logger.info("OAuth2 clientRegistration : " + clientRegistration);
        // logger.info("OAuth2 authorizedClient : " + authorizedClient);
        // logger.info("OAuth2 principalName : " + principalName);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("username", principalName);
        parameters.add("raw_name", name);
        parameters.add("raw_info", userinfo);
        parameters.add("raw_token", accessToken);
        parameters.add("token_type", tokenType);
        parameters.add("id_token", idToken);
        return parameters;
    }

    protected String callback(HttpServletRequest request, Authentication authentication) {

        OAuth2AuthorizationRequest authorizationRequest = authorizationRequestRepository
                .loadAuthorizationRequest(request);
        String callback = authorizationRequest != null ? authorizationRequest.getRedirectUri() : "";
        if(StringUtils.hasText(callback)) 
            return callback;

        Object value = WebUtils.getSessionAttribute(request, "callback");
        if(ObjectUtils.isEmpty(value)) return "";
        return value.toString();
    }	
}
