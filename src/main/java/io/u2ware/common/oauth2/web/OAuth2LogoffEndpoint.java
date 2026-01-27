package io.u2ware.common.oauth2.web;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OAuth2LogoffEndpoint {
    
    protected final Log logger = LogFactory.getLog(getClass());
    
    @RequestMapping("/oauth2/logoff")
    public @ResponseBody ResponseEntity<Object> oauth2Logoff(){
        logger.info("\t[/oauth2/logoff]: ");

        Map<String,Object> response = new HashMap<>();
        response.put("logoff", "success");
        return ResponseEntity.ok(response);
    }

}
