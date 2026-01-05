package io.u2ware.common.oauth2.jwt;

import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.ObjectUtils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;

public class JwtConfiguration {


    private JwtConfiguration(){}

    /////////////////////////////////////////////////
    //
    /////////////////////////////////////////////////
    public static JWKSource<SecurityContext> source(RSAKey jwk) throws Exception{
        JWKSet jwkSet = new JWKSet(jwk);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
        return jwkSource;
    }

    public static JWKSet set(JWKSource<SecurityContext> jwkSource) throws Exception{
        JWKSelector jwkSelector = new JWKSelector((new JWKMatcher.Builder()).build());
        return new JWKSet(jwkSource.get(jwkSelector, (SecurityContext)null)); 
    }


    public static NimbusJwtEncoder encoder(JWKSource<SecurityContext> jwkSource)throws Exception{
        return new NimbusJwtEncoder(jwkSource);
    }

    public static NimbusJwtDecoder decoder(JWKSource<SecurityContext> jwkSource)throws Exception{

        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        jwsAlgs.addAll(JWSAlgorithm.Family.SIGNATURE);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

        return new NimbusJwtDecoder(jwtProcessor);
    }




    //////////////////////////////////////////
    //
    //////////////////////////////////////////
    public static boolean hasDecoder(OAuth2ResourceServerProperties properties) {
        Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
        String jwkSetUri = properties.getJwt().getJwkSetUri();
        if(! ObjectUtils.isEmpty(publicKeyLocation)) {
            return true;
        }
        if(! ObjectUtils.isEmpty(jwkSetUri)) {
            return true;
        }
        return false;
    }

    public static JwtDecoder decoder(OAuth2ResourceServerProperties properties, JwtDecoder... decoders) throws Exception{

        Collection<JwtDecoder> collection = Arrays.asList(decoders);

        Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
        String jwkSetUri = properties.getJwt().getJwkSetUri();

        if(! ObjectUtils.isEmpty(publicKeyLocation)) {
            // logger.info("NimbusJwtDecoder by publicKeyLocation");
            Path path = Path.of(publicKeyLocation.getURI());
            RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);
            collection.add(NimbusJwtDecoder.withPublicKey(publicKey).build());   
        }
        if(! ObjectUtils.isEmpty(jwkSetUri)) {
            collection.add(NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build());   
        }
        return new JwtCompositeDecoder(collection);
    }


    public static JwtAuthenticationConverter converter(Converter<Jwt,Collection<GrantedAuthority>> customJwtGrantedAuthoritiesConverter) {

        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = null;
        if(customJwtGrantedAuthoritiesConverter == null) {
            JwtGrantedAuthoritiesConverter c = new JwtGrantedAuthoritiesConverter();
            c.setAuthoritiesClaimName("authorities");
            c.setAuthorityPrefix("");
            jwtGrantedAuthoritiesConverter = c;
        }else{
            jwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
        }

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
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
}
