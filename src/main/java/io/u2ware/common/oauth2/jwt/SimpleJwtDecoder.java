package io.u2ware.common.oauth2.jwt;

import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.ObjectUtils;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JoseKeyCodec;

public class SimpleJwtDecoder implements JwtDecoder {

	protected Log logger = LogFactory.getLog(getClass());



    public static boolean available(OAuth2ResourceServerProperties properties){

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




    private Collection<JwtDecoder> decoders = new ArrayList<>();

    public SimpleJwtDecoder(JWKSource<SecurityContext> jwkSource, OAuth2ResourceServerProperties properties){
        this(properties);
        try{
            JwtDecoder decoder1 = JoseKeyCodec.decoder(jwkSource);
            decoders.add(decoder1);
        }catch(Exception e){
            logger.warn("", e);
        }
    }


    public SimpleJwtDecoder(OAuth2ResourceServerProperties properties){
        try{
            Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
            String jwkSetUri = properties.getJwt().getJwkSetUri();

            if(! ObjectUtils.isEmpty(publicKeyLocation)) {
                Path path = Path.of(publicKeyLocation.getURI());
                RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);

                JwtDecoder decoder2 = NimbusJwtDecoder.withPublicKey(publicKey).build();
                decoders.add(decoder2);
            }
            if(! ObjectUtils.isEmpty(jwkSetUri)) {
                JwtDecoder decoder2 = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
                decoders.add(decoder2);
            }

        }catch(Exception e){
            logger.warn("", e);
        }
    }

    @Override
    public Jwt decode(String token) {
        
        for(JwtDecoder decoder : decoders) {
            try {
                return decoder.decode(token);
            }catch(Exception e) {
                // logger.warn("", e);
            }
        }
        throw new RuntimeException("JwtCompositeDecoder decode fail");
    }   
}
