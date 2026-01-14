package io.u2ware.common.oauth2.jwt;

import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.util.ClassUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.WebUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JoseKeyCodec;
import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;
import jakarta.servlet.http.HttpServletRequest;


public class OAuth2ResourceServerAdministration {


    private SecurityProperties securityProperties;
    private OAuth2ResourceServerProperties oauth2Properties;

    private JWKSource<SecurityContext> jwkSource;
    private JWKSet jwkSet;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private boolean available =false;

    // private OAuth2ResourceServerUserinfoService oauth2UserinfoService;

    // public OAuth2ResourceServerAdministration(SecurityProperties p1, OAuth2ResourceServerProperties p2, OAuth2ResourceServerUserinfoService oauth2UserinfoService) {
    //     this(p1, p2);
    //     this.oauth2UserinfoService = oauth2UserinfoService;
    // }


    public OAuth2ResourceServerAdministration(SecurityProperties p1, OAuth2ResourceServerProperties p2) {

        this.securityProperties = p1;
        this.oauth2Properties = p2;

        String username = securityProperties.getUser().getName();
        String password = securityProperties.getUser().getPassword();
        System.err.println("\n");
        System.err.println("\t username: "+username);
        System.err.println("\t password: "+password);
        System.err.println("\n");


        try {
            this.jwkSource = JoseKeyCodec.source(JoseKeyGenerator.generateRsa());
            this.jwkSet = JoseKeyCodec.jwk(jwkSource);
            this.jwtEncoder = JoseKeyCodec.encoder(jwkSource);
           
            JwtDecoder decoder = JoseKeyCodec.decoder(jwkSource);
            List<JwtDecoder> collection = new ArrayList<>(Arrays.asList(decoder))  ;

            Resource publicKeyLocation = oauth2Properties.getJwt().getPublicKeyLocation();
            String jwkSetUri = oauth2Properties.getJwt().getJwkSetUri();

            if(! ObjectUtils.isEmpty(publicKeyLocation)) {
                Path path = Path.of(publicKeyLocation.getURI());
                RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);
                collection.add(NimbusJwtDecoder.withPublicKey(publicKey).build());  
                this.available = true; 
            }
            if(! ObjectUtils.isEmpty(jwkSetUri)) {
                collection.add(NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build());   
                this.available = true; 
            }
            this.jwtDecoder = new JwtCompositeDecoder(collection);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static class JwtCompositeDecoder implements JwtDecoder {

        private Collection<JwtDecoder> decoders;

        private JwtCompositeDecoder(Collection<JwtDecoder> decoders) {
            this.decoders = decoders;
        }

        @Override
        public Jwt decode(String token) {
            for(JwtDecoder decoder : decoders) {
                try {
                    return decoder.decode(token);
                }catch(Exception e) {
                }
            }
            throw new RuntimeException("JwtCompositeDecoder decode fail");
        }        
    }

    public JWKSource<SecurityContext> jwkSource() {
        return jwkSource;
    }   
    public JWKSet jwkSet() {
        return jwkSet;
    }
    public JwtEncoder jwtEncoder() {
        return jwtEncoder;
    }
    public JwtDecoder jwtDecoder() {
        return jwtDecoder;
    }

    public boolean available() {
        return available;
    }

    //////////////////////////////////////////
    //
    //////////////////////////////////////////
    public JwtAuthenticationConverter jwtConverter() {
        return jwtConverter(new JwtDefaultConverter());
    }

    public JwtAuthenticationConverter jwtConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverters) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverters);
        return jwtAuthenticationConverter;
    }

    private static class JwtDefaultConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        protected Log logger = LogFactory.getLog(getClass());

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            logger.info("JwtGrantedAuthoritiesConverter: "+jwt.getSubject());
            Collection<GrantedAuthority> authorities = AuthenticationContext.authorities(jwt);
            logger.info("JwtGrantedAuthoritiesConverter : "+authorities);       
            return authorities;
        }
    }


    // public JwtAuthenticationConverter build(Converter<Jwt, Collection<GrantedAuthority>> customJwtGrantedAuthoritiesConverter){
    //     Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = null;
    //     if(customJwtGrantedAuthoritiesConverter == null) {
    //         JwtGrantedAuthoritiesConverter c = new JwtGrantedAuthoritiesConverter();
    //         c.setAuthoritiesClaimName("authorities");
    //         c.setAuthorityPrefix("");
    //         jwtGrantedAuthoritiesConverter = c;
    //     }else{
    //         jwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
    //     }
    //     JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    //     jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
    //     return jwtAuthenticationConverter;
    // }


    //////////////////////////////////////////
    //
    //////////////////////////////////////////
    public UserDetailsService userDetailsService() {
        return new JwtUserDetailsService(null, this.securityProperties);
    }
    public UserDetailsService userDetailsService(OAuth2ResourceServerUserinfoService service) {
        return new JwtUserDetailsService(service, this.securityProperties);
    }

    private static class JwtUserDetailsService implements UserDetailsService{

        protected Log logger = LogFactory.getLog(getClass());

        protected OAuth2ResourceServerUserinfoService service;
        protected SecurityProperties securityProperties;

        protected JwtUserDetailsService(OAuth2ResourceServerUserinfoService service, SecurityProperties securityProperties){
            this.service = service;
            this.securityProperties = securityProperties;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

            logger.info("JwtUserDetailsService: "+username);

            if(service != null) {
                return service.loadUserByUsername(username);
            }
            
            if(!this.securityProperties.getUser().getName().equals(username)) {
                throw new UsernameNotFoundException("User not found: " + username);
            }
            UserDetails userDetails = User.builder()
                .username(securityProperties.getUser().getName())
                .password("{bcrypt}"+securityProperties.getUser().getPassword())
                .roles("ADMIN")
                .build();
            return userDetails;            
        }
    }


    //////////////////////////////////////////
    //
    //////////////////////////////////////////
    public JwtEndpoints jwtEndpoints() {
        return new JwtEndpoints(this.jwtEncoder, this.jwtDecoder, null);
    }
    public JwtEndpoints jwtEndpoints(OAuth2ResourceServerUserinfoService service) {
        return new JwtEndpoints(this.jwtEncoder, this.jwtDecoder, service);
    }

    @RestController
    public static class JwtEndpoints {


        protected Log logger = LogFactory.getLog(getClass());


        private OAuth2ResourceServerUserinfoService service;
        private JwtEncoder jwtEncoder;
        private JwtDecoder jwtDecoder;

        protected JwtEndpoints(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, OAuth2ResourceServerUserinfoService service){
            this.jwtEncoder = jwtEncoder;
            this.jwtDecoder = jwtDecoder;
            this.service = service;
        }


        @GetMapping(value = "/oauth2/providers")
        public @ResponseBody List<Map<String,String>> oauth2Providers(HttpServletRequest request) {

            String clientRegistrationId = ClassUtils.getShortName(getClass());

            List<Map<String,String>> clients = new ArrayList<>();

            UriComponents uri = ServletUriComponentsBuilder.fromContextPath(request)
                    .path("/oauth2/login")
                    .queryParam("provider", clientRegistrationId)
                    .queryParam("callback", "")
                    .build();

            Map<String,String> client = new HashMap<>();
            client.put("name", clientRegistrationId);
            client.put("uri", uri.toString());
            clients.add(client);                    

            return clients;
        }

        @GetMapping(value = "/oauth2/login", params = {"provider", "callback"})
        public @ResponseBody ResponseEntity<Object> oauth2Login(HttpServletRequest request,
                @RequestParam("provider") String provider,
                @RequestParam("callback") String callback) {


            String clientRegistrationId = ClassUtils.getShortName(getClass());
            if (! clientRegistrationId.equalsIgnoreCase(provider))
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();

            saveCallback(request, callback);

            UriComponents authorization = ServletUriComponentsBuilder.fromCurrentContextPath()
                    .path("/login")
                    .build();

            logger.info("OAuth2 Login: " + authorization);
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(authorization.toUri());
            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();
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


        @GetMapping(value = "/oauth2/logon")
        public @ResponseBody ResponseEntity<Object> oauth2Logon(HttpServletRequest request, Authentication authentication ) {

            logger.info("OAuth2 Logon: " + authentication);
            logger.info("OAuth2 Logon: " + authentication.getClass());
            logger.info("OAuth2 Logon: " + authentication.getName());

            String principalName = authentication.getName();

            Jwt jwt = JoseKeyEncryptor.encrypt(jwtEncoder, (claims)-> { 
                claims.put("sub", principalName);
                claims.put("email", principalName);
                claims.put("name", principalName);
            });

            String userinfo = ServletUriComponentsBuilder.fromContextPath(request).path("/oauth2/userinfo").build().toUriString();
            String accessToken = jwt.getTokenValue();
            String tokenType = "Bearer";
            String idToken = jwt.getTokenValue();
            String redirectUri = loadCallBack(request);

            UriComponents callback = UriComponentsBuilder
                    .fromUriString(redirectUri)
                    .queryParam("username", principalName)
                    .queryParam("raw_info", userinfo)
                    .queryParam("raw_token", accessToken)
                    .queryParam("token_type", tokenType)
                    .queryParam("id_token", idToken)
                    .build();

            logger.info("OAuth2 Logon : "+callback);

            if(StringUtils.hasText(redirectUri)) {
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(callback.toUri());
                return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();

            }else{
                return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(callback.getQueryParams());
            }
        }



        @RequestMapping("/oauth2/logout")
        public @ResponseBody ResponseEntity<Object> oauth2Logout(HttpServletRequest request){
            UriComponents logout = ServletUriComponentsBuilder.fromContextPath(request)
                    .path("/logout")
                    .build();

            logger.info("OAuth2 Logout : "+logout);
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(logout.toUri());
            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).headers(headers).build();
        }


        @RequestMapping("/oauth2/logoff")
        public @ResponseBody ResponseEntity<Object> oauth2Logoff(){
            logger.info("OAuth2 Logoff:");

            Map<String,Object> response = new HashMap<>();
            response.put("logoff", "success");
            return ResponseEntity.ok(response);
        }

        @GetMapping(value = "/oauth2/userinfo")
        public @ResponseBody ResponseEntity<Object> oauth2UserInfo(HttpServletRequest request) {


            String token = AuthenticationContext.extractHeaderToken(request);
            Jwt jwt = null;

            try{
                jwt = JoseKeyEncryptor.decrypt(jwtDecoder, () -> token);
            }catch(Exception e){
                logger.info("JoseKeyEncryptor: "+token, e);
                return ResponseEntity.status(HttpStatusCode.valueOf(401)).build();
            }

            if(this.service != null) {
                try{
                    String username = jwt.getSubject();
                    return ResponseEntity.ok(service.loadUserByUsername(username));

                }catch(Exception e){
                    logger.info("Oauth2UserinfoService: "+token, e);
                    return ResponseEntity.status(HttpStatusCode.valueOf(401)).build();
                }
            }else{
                return ResponseEntity.ok(jwt);
            }
       }
    }
}
