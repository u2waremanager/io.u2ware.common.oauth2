package io.u2ware.common.oauth2.security;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class OAuth2ResourceServerUserinfoEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());


    private SimpleJwtAuthenticationMapper mapper = new SimpleJwtAuthenticationMapper.Default();

    public OAuth2ResourceServerUserinfoEndpoint(SimpleJwtAuthenticationMapper mapper){
        if(mapper == null) return;
        this.mapper = mapper;
    }   



    @RequestMapping(value = "/oauth2/userinfo", method = { RequestMethod.GET })
    public @ResponseBody ResponseEntity<Object> oauth2UserInfo(HttpServletRequest request, Authentication authentication) {
        try{
            if(authentication == null) {
                throw new NullPointerException("authentication is null");
            }
            if(! (authentication instanceof JwtAuthenticationToken)) {
                throw new NullPointerException("authentication is not JWT");
            }

            logger.info("UserinfoToken : "+authentication);
            logger.info("UserinfoToken : "+authentication.getClass());

            JwtAuthenticationToken token = (JwtAuthenticationToken)authentication;

            Map<String,Object> response = mapper.map(token);

            logger.info("\t[/oauth2/userinfo]: Done.");
            return ResponseEntity.ok(response);

        }catch(Exception e){
            logger.info("\t[/oauth2/userinfo]: "+e.getMessage());
            Map<String, String> error = Map.of(
                "username", "Anonymous",
                "error", e.getMessage()
            );
            return ResponseEntity.ok(error);
        }
    }
}
