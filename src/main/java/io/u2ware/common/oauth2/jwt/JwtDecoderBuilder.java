package io.u2ware.common.oauth2.jwt;

import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.IntStream;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.ObjectUtils;

import com.nimbusds.jose.jwk.RSAKey;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.crypto.JoseKeyEncryptor;
import io.u2ware.common.oauth2.crypto.JoseKeyGenerator;

public class JwtDecoderBuilder {
    
    public JwtDecoder build(OAuth2ResourceServerProperties properties) {

        try{
            Resource publicKeyLocation = properties.getJwt().getPublicKeyLocation();
            String jwkSetUri = properties.getJwt().getJwkSetUri();

            if(! ObjectUtils.isEmpty(publicKeyLocation)) {
                // logger.info("NimbusJwtDecoder by publicKeyLocation");
                Path path = Path.of(publicKeyLocation.getURI());
                RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);
                return NimbusJwtDecoder.withPublicKey(publicKey).build();
            }

            if(! ObjectUtils.isEmpty(jwkSetUri)) {
                // logger.info("NimbusJwtDecoder by jwkSetUri");
                return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            }

            // logger.info("NimbusJwtDecoder by new RSA Key");
            RSAKey rsaKey = JoseKeyGenerator.generateRsa();
            System.err.println("\n");
            IntStream.range(1, 6).forEach(i->{

                String name = "test_account_0"+i;
                Jwt jwt = JoseKeyEncryptor.encrypt(rsaKey, claims->{
                    claims.put("sub", name);
                    claims.put("email", name);
                    claims.put("name", name);
                });
                System.err.println("#VITE_API_TOKEN="+jwt.getTokenValue());
            });
            System.err.println("\n");

            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            return NimbusJwtDecoder.withPublicKey(publicKey).build();

        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }


    private JwtDecoderBuilder(){
    }

    private static JwtDecoderBuilder instance;

    public static JwtDecoderBuilder getInstance(){
        if(instance == null) {
            instance = new JwtDecoderBuilder();
        }
        return instance;
    }
}
