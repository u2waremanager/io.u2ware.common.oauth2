package io.u2ware.common.oauth2.webmvc;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.u2ware.common.oauth2.crypto.JoseEncryptor;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
@Controller
public class AuthorizationEndpoints {

    protected Log logger = LogFactory.getLog(getClass());

    @Autowired
    public ObjectMapper objectMapper;


    @GetMapping(value = "/oauth2/userinfo")
    public @ResponseBody ResponseEntity<Object> oauth2UserInfo(Authentication authentication) {

        logger.info("oauth2UserInfo : "+authentication);
        try {
            Jwt jwt = AuthenticationContext.authenticationToken(authentication);

            Collection<GrantedAuthority> securityAuthorities = AuthenticationContext.authorities(authentication);
            logger.info("securityAuthorities : "+securityAuthorities);

            Collection<GrantedAuthority> jwtAuthorities = AuthenticationContext.authorities(jwt);
            logger.info("jwtAuthorities : "+jwtAuthorities);


            Set<String> responseAuthorities = new HashSet<>();
            if(securityAuthorities != null) {
                responseAuthorities.addAll(securityAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
            }
            if(jwtAuthorities != null) {
                responseAuthorities.addAll(jwtAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
            }
            logger.info("responseAuthorities : "+responseAuthorities);

            Map<String,Object> claims = jwt.getClaims();
            Map<String,Object> responseClaims = new HashMap<>(claims);
            responseClaims.put("authorities", responseAuthorities);

            @SuppressWarnings("unchecked")
            Map<String,Object> responseJwt = objectMapper.convertValue(jwt, Map.class);
            responseJwt.put("claims", responseClaims);

            return ResponseEntity.ok(responseJwt);

        } catch (Exception e) {
            // e.printStackTrace();
            return ResponseEntity.status(HttpStatusCode.valueOf(401)).body(e.getMessage());
        }
    }

    @GetMapping(value = "/oauth2/providers")
    public @ResponseBody ResponseEntity<Object> oauth2Providers(HttpServletRequest request) {

        if(JoseEncryptor.unavailable()){
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }

        try{
            UriComponents uri = ServletUriComponentsBuilder.fromContextPath(request)
            .path("/oauth2/login")
            .queryParam("provider", "{provider}")
            .queryParam("callback", "{callback}")
            .build();

            ArrayList<Object> providers = new ArrayList<>();
            Map<String, Object> provider = new HashMap<>();
            provider.put("name", "Test Oauth2");
            provider.put("uri", uri.toUriString());
            providers.add(provider);

            return ResponseEntity.ok(providers);

        }catch(Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }
    }


    @PostMapping(value = "/oauth2/login", params = { "provider"})
    public @ResponseBody ResponseEntity<Object> oauth2Login(HttpServletRequest request,
            @RequestParam("provider") String provider) {

        if(JoseEncryptor.unavailable()){
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }

        try{
            Jwt jwt = JoseEncryptor.getInstance().encrypt((claims)->{
                claims.put("sub", provider);
                claims.put("email", provider);
                claims.put("name", provider);
            });    
            String idToken = jwt.getTokenValue();            
            return ResponseEntity.ok(idToken);//.status(HttpStatus.OK).c.headers(headers).build();

        }catch(Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }
    }



    @GetMapping(value = "/oauth2/login", params = { "provider", "callback" })
    public @ResponseBody ResponseEntity<Object> oauth2Login(HttpServletRequest request,
            @RequestParam("provider") String provider, @RequestParam("callback") String callback) {

        if(JoseEncryptor.unavailable()){
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }

        try{
            Jwt jwt = JoseEncryptor.getInstance().encrypt((claims)->{
                claims.put("sub", provider);
                claims.put("email", provider);
                claims.put("name", provider);
            });
            
            String userinfo = ServletUriComponentsBuilder
                .fromContextPath(request)
                .path("/oauth2/userinfo")
                .build()
                .toString();
            String tokenType = "Bearer";
            String principalName = provider;
            String accessToken = jwt.getTokenValue();
            String idToken = jwt.getTokenValue();
    
            UriComponents location = UriComponentsBuilder
                    .fromUriString(callback)
                    .queryParam("username", principalName)
                    .queryParam("raw_info", userinfo)
                    .queryParam("raw_token", accessToken)
                    .queryParam("token_type", tokenType)
                    .queryParam("id_token", idToken)
                    .build();
    
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(location.toUri());
            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();
    
        }catch(Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }
    }

    @GetMapping(value = "/oauth2/logout")
    public @ResponseBody ResponseEntity<Object> oauth2Logout() {       

        if(JoseEncryptor.unavailable()){
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).build();
        }        
        return ResponseEntity.ok("OK");
    }    
}
