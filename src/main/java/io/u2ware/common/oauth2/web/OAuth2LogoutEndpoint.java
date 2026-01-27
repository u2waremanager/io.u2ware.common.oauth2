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
public class OAuth2LogoutEndpoint {

    protected final Log logger = LogFactory.getLog(getClass());


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



}
