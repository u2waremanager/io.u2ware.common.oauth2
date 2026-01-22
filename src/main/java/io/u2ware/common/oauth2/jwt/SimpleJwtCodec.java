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
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.ObjectUtils;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JoseKeyCodec;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;

public class SimpleJwtCodec implements JwtDecoder , JwtEncoder{

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

    private static JWKSource<SecurityContext> testSource;
    static {
        try {
            testSource = JoseKeyCodec.source(JoseKeyGenerator.generateRsa());
        } catch (Exception e) {
        }
    }


    private Collection<JwtDecoder> decoders = new ArrayList<>();
    private Collection<JwtEncoder> encoders = new ArrayList<>();

    //For auth server
    public SimpleJwtCodec(JWKSource<SecurityContext> jwkSource){
        this.jwtDecoder(decoders, jwkSource);
        logger.info("JwtDecoders: "+decoders);
        logger.info("JwtEncoders: "+encoders);
    }

    //For resource server
    public SimpleJwtCodec(OAuth2ResourceServerProperties properties){
        this.jwtDecoder(decoders, properties);
        this.jwtDecoder(decoders, testSource);
        this.jwtEncoder(encoders, testSource);
        logger.info("JwtDecoders: "+decoders);
        logger.info("JwtEncoders: "+encoders);
    }

    //For resource server self auth
    public SimpleJwtCodec(JWKSource<SecurityContext> jwkSource, OAuth2ResourceServerProperties properties){
        this.jwtDecoder(decoders, jwkSource);
        this.jwtDecoder(decoders, properties);
        this.jwtEncoder(encoders, jwkSource);
        logger.info("JwtDecoders: "+decoders);
        logger.info("JwtEncoders: "+encoders);
    }


    private JwtEncoder jwtEncoder(Collection<JwtEncoder> encoders, JWKSource<SecurityContext> jwkSource){
        try{
            JwtEncoder encoder = JoseKeyCodec.encoder(jwkSource);
            encoders.add(encoder);
            return encoder;
        }catch(Exception e){
            logger.warn("", e);
            return null;
        }
    }

    private JwtDecoder jwtDecoder(Collection<JwtDecoder> decoders, JWKSource<SecurityContext> jwkSource){
        try{
            JwtDecoder decoder = JoseKeyCodec.decoder(jwkSource);
            decoders.add(decoder);
            return decoder;
        }catch(Exception e){
            logger.warn("", e);
            return null;
        }
    }

    private JwtDecoder jwtDecoder(Collection<JwtDecoder> decoders, OAuth2ResourceServerProperties properties){
        try{
            Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
            String jwkSetUri = properties.getJwt().getJwkSetUri();
            if(! ObjectUtils.isEmpty(publicKeyLocation)) {
                Path path = Path.of(publicKeyLocation.getURI());
                RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);
                decoders.add(NimbusJwtDecoder.withPublicKey(publicKey).build());
            }
            if(! ObjectUtils.isEmpty(jwkSetUri)) {
                decoders.add(NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build());
            }
            return null;
        }catch(Exception e){
            logger.warn("", e);
            return null;
        }
    }

    @Override
    public Jwt decode(String token) {
        for(JwtDecoder decoder : decoders) {
            try {
                return decoder.decode(token);
            }catch(Exception e) {
                // logger.info("decode", e);
            }
        }
        throw new RuntimeException("SimpleJwtCodec decode fail");
    }

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        for(JwtEncoder encoder : encoders) {
            try {
                return encoder.encode(parameters);
            }catch(Exception e) {
                // logger.info("encode", e);
            }
        }
        throw new RuntimeException("SimpleJwtCodec encode fail");
    }   
}
