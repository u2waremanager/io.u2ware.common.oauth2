package io.u2ware.common.oauth2.web;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


// @Component
public class OAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private Log logger = LogFactory.getLog(getClass());

    private Map<String, OAuth2AuthorizationRequest> authorizationRequests = new ConcurrentHashMap<>();
    private Map<String, String> callbackRequests = new ConcurrentHashMap<>();


    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");

        if (authorizationRequest == null) {
            this.removeAuthorizationRequest(request, response);
            return;
        } 

        String state = authorizationRequest.getState();
        Assert.hasText(state, "authorizationRequest.state cannot be empty");
        logger.info("\t saveAuthorizationRequest: " + state);

        String key = getAuthorizationRequestKey(request, state);
        authorizationRequests.put(key, authorizationRequest);
        logger.info("\t saveAuthorizationRequest: " + key);
        logger.info("\t saveAuthorizationRequest: " + authorizationRequest);

        String callback = request.getParameter("callback");
        if (StringUtils.hasText(callback)) {
            callbackRequests.put(key, request.getParameter("callback"));
            logger.info("\t saveAuthorizationRequest: " + callback);
        }
    }


    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {

        Assert.notNull(request, "request cannot be null");

        String state = request.getParameter(OAuth2ParameterNames.STATE);
        logger.info("\t removeAuthorizationRequest: " + state);
        if (state == null) {
            return null;
        }


        String key = getAuthorizationRequestKey(request, state);
        OAuth2AuthorizationRequest authorizationRequest = authorizationRequests.remove(key);
        logger.info("\t removeAuthorizationRequest: " + key);
        logger.info("\t removeAuthorizationRequest: " + authorizationRequest);


        String callback = callbackRequests.remove(key);
        if (StringUtils.hasText(callback)) {
            saveCallback(request, callback);
            logger.info("\t removeAuthorizationRequest : " + callback);
        }

        return authorizationRequest;
    }

    private String saveCallback(HttpServletRequest request, String value) {
         WebUtils.setSessionAttribute(request, "callback", value);
         return value;
    }
    private String loadCallBack(HttpServletRequest request) {
         Object value = WebUtils.getSessionAttribute(request, "callback");
         if(ObjectUtils.isEmpty(value)) return "";
         return value.toString();
    }



    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {

        Assert.notNull(request, "request cannot be null");

        String state = request.getParameter(OAuth2ParameterNames.STATE);
        logger.info("\t loadAuthorizationRequest : " + state);

        if (state == null) {

            String callback = loadCallBack(request);

            if (StringUtils.hasText(callback)) {
                logger.info("\t loadAuthorizationRequest : " + callback);
                //Return Fake OAuth2AuthorizationRequest
                return OAuth2AuthorizationRequest
                        .authorizationCode()
                        .authorizationRequestUri(callback)
                        .authorizationUri(callback)
                        .clientId(callback)
                        .redirectUri(callback).build();

            }else{
                return null;
            }
        } else {
            String key = getAuthorizationRequestKey(request, state);
            OAuth2AuthorizationRequest authorizationRequest = authorizationRequests.get(key);
            logger.info("\t loadAuthorizationRequest : " + key);
            logger.info("\t loadAuthorizationRequest : " + authorizationRequests);
            return authorizationRequest;
        }
    }



    private String getAuthorizationRequestKey(HttpServletRequest request, String state) {
        UriComponents c = UriComponentsBuilder.fromPath(request.getRequestURI()).build();
        String lastSegment = c.getPathSegments().stream().reduce((first, second) -> second).orElse(null);
        return lastSegment + "/" + state;
    }
    

}
