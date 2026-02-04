package io.u2ware.common.oauth2.jwt;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class UserinfoEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());

    private @Autowired ObjectMapper mapper;

    @RequestMapping(value = "/oauth2/userinfo", method = { RequestMethod.GET })
    public @ResponseBody ResponseEntity<Object> oauth2UserInfo(HttpServletRequest request, Authentication authentication) {
        try{
            if(authentication == null) {
                throw new NullPointerException("authentication is null");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> response = mapper.convertValue(authentication, Map.class);


            List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

            Jwt jwt = (Jwt)authentication.getPrincipal();
            String username = jwt.getClaimAsString("name");

            response.put("username", username);
            response.put("authorities", authorities);

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
