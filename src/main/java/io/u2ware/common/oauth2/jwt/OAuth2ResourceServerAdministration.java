package io.u2ware.common.oauth2.jwt;

import java.io.IOException;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JoseKeyCodec;
import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;
import io.u2ware.common.oauth2.jwt.AuthenticationContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class OAuth2ResourceServerAdministration {


    private SecurityProperties securityProperties;
    private OAuth2ResourceServerProperties oauth2Properties;

    private JWKSource<SecurityContext> jwkSource;
    private JWKSet jwkSet;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    public OAuth2ResourceServerAdministration(SecurityProperties securityProperties,
            OAuth2ResourceServerProperties oauth2Properties) {

        this.securityProperties = securityProperties;
        this.oauth2Properties = oauth2Properties;


        System.err.println("");
        if(! StringUtils.hasText(securityProperties.getUser().getName())) {
            String username = UUID.randomUUID().toString();
            System.err.println("username: "+username);
            securityProperties.getUser().setName(username);        
        }

        if(! StringUtils.hasText(securityProperties.getUser().getPassword())) {
            String password = UUID.randomUUID().toString();
            System.err.println("password: "+password);
            securityProperties.getUser().setPassword(password);        
        }
        System.err.println("");


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
            }
            if(! ObjectUtils.isEmpty(jwkSetUri)) {
                collection.add(NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build());   
            }
            this.jwtDecoder = new JwtCompositeDecoder(collection);

        } catch (Exception e) {
            throw new RuntimeException(e);
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





    



    //////////////////////////////////////////
    //
    //////////////////////////////////////////
    public boolean available() {
        Resource publicKeyLocation = oauth2Properties.getJwt().getPublicKeyLocation();
        String jwkSetUri = oauth2Properties.getJwt().getJwkSetUri();
        if(! ObjectUtils.isEmpty(publicKeyLocation)) {
            return true;
        }
        if(! ObjectUtils.isEmpty(jwkSetUri)) {
            return true;
        }
        return false;
    }

    public JwtAuthenticationConverter jwtConverter() {
        return jwtConverter(new JwtDefaultConverter());
    }

    public JwtAuthenticationConverter jwtConverter(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverters) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverters);
        return jwtAuthenticationConverter;
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



    public UserDetailsService userDetailsService() {
        return new JwtUserDetailsService(this.securityProperties);
    }

    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new JwtAuthenticationSuccessHandler(this.jwtEncoder);
    }


    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new JwtAuthenticationFailureHandler();
    }


    private static class JwtUserDetailsService implements UserDetailsService{

        protected Log logger = LogFactory.getLog(getClass());

        protected SecurityProperties securityProperties;

        protected JwtUserDetailsService(SecurityProperties securityProperties){
            this.securityProperties = securityProperties;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

            logger.info("JwtUserDetailsService: "+username);

            if(!this.securityProperties.getUser().getName().equals(username)) {
                throw new UsernameNotFoundException("User not found: " + username);
            }


            UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username(securityProperties.getUser().getName())
                .password(securityProperties.getUser().getPassword())
                .roles("ADMIN")
                .build();

            return userDetails;
        }
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


    private static class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

        protected Log logger = LogFactory.getLog(getClass());

        private JwtEncoder jwtEncoder;

        public JwtAuthenticationSuccessHandler(JwtEncoder jwtEncoder) {
            this.jwtEncoder = jwtEncoder;
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

            logger.info("onAuthenticationSuccess");

            Jwt token = JoseKeyEncryptor.encrypt(jwtEncoder, claims->{
                claims.put("sub", authentication.getName());
                claims.put("email", authentication.getName());
                claims.put("name", authentication.getName());
                claims.put("hello", "jose");
                Collection<String> authorities = Arrays.asList("ROLE_ADMIN");
                claims.put("authorities", authorities);
            });

            // response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write(token.getTokenValue());  
            response.getWriter().flush();
            response.getWriter().close();            
        }       
    }

    private static class JwtAuthenticationFailureHandler implements AuthenticationFailureHandler {

        protected Log logger = LogFactory.getLog(getClass());


        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            
            logger.info("onAuthenticationFailure");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(exception.getMessage());  
            response.getWriter().flush();
            response.getWriter().close();   
        }
    }
}
