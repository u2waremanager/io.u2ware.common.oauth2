package io.u2ware.common.oauth2.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.jose.JWKCodec;
import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;
import io.u2ware.common.oauth2.jwt.JwtConfiguration;

public class JoseKeyEncryptorTests {
    
    private Log logger = LogFactory.getLog(getClass());


    private Consumer<Map<String,Object>> claims(String subject) throws Exception{
        return (claims)->{
            claims.put("sub", subject);
            claims.put("email", subject);
            claims.put("name", subject);            
        };
    }


	@Test
    public void context1Loads() throws Exception {

     
        RSAKey key = JoseKeyGenerator.generateRsa();
        JWKSource<SecurityContext> jwkSource = JWKCodec.source(key);
        NimbusJwtEncoder encoder = JWKCodec.encoder(jwkSource);
        NimbusJwtDecoder decoder = JWKCodec.decoder(jwkSource);


        Jwt jwt1 = JoseKeyEncryptor.encrypt(encoder, claims("user1"));
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(decoder, () -> jwt1.getTokenValue());
        logger.info(jwt2);
        logger.info(jwt2.getTokenValue());
    }

	@Test
    public void context2Loads() throws Exception {

        RSAKey key1 = JoseKeyGenerator.generateRsa();
        RSAKey key2 = JoseKeyGenerator.generateRsa();

        JWKSource<SecurityContext> jwkSource1 = JWKCodec.source(key1);
        NimbusJwtEncoder encoder1 = JWKCodec.encoder(jwkSource1);
        // NimbusJwtDecoder decoder1 = JoseKeyCodec.decoder(jwkSource1);


        JWKSource<SecurityContext> jwkSource2 = JWKCodec.source(key2);
        // NimbusJwtEncoder encoder2 = JoseKeyCodec.encoder(jwkSource2);
        NimbusJwtDecoder decoder2 = JWKCodec.decoder(jwkSource2);


        Jwt t1 = JoseKeyEncryptor.encrypt(encoder1, claims("user1"));
        logger.info(t1);
        logger.info(t1.getTokenValue());

        try{
            Jwt t2 = JoseKeyEncryptor.decrypt(decoder2, () -> t1.getTokenValue());
            logger.info(t2);
            logger.info(t2.getTokenValue());

        }catch(Exception e){
            logger.info(e.getMessage());
            assertThat(e).isNotNull();
        }
    }


}