package io.u2ware.common.oauth2.crypto;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jose.jwk.RSAKey;

public class JoseKeyFilesTests {
    
    private Log logger = LogFactory.getLog(getClass());



	@Test
    public void context1Loads() throws Exception {

        RSAKey rsaKey = JoseKeyGenerator.generateRsa();

        Path p1 = Paths.get("target/private_key.jwk");
        Path p2 = Paths.get("target/public_key.jwk");

        JoseKeyFiles.writeRSAPrivateKey(p1, rsaKey);
        JoseKeyFiles.writeRSAPublicKey(p2, rsaKey);
        
        RSAKey rsaKey1 = JoseKeyFiles.readRSAPrivateKey(p1);
        RSAKey rsaKey2 = JoseKeyFiles.readRSAPublicKey(p2);

        logger.info(rsaKey1);
        logger.info(rsaKey2);


        Jwt jwt1 = JoseKeyEncryptor.encrypt(rsaKey1, (claims)->{
            claims.put("sub", "user1");
            claims.put("email", "user1");
            claims.put("name", "user1");            
        });
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(rsaKey2, () -> jwt1.getTokenValue());
        logger.info(jwt2);
        logger.info(jwt2.getTokenValue());

        Assertions.assertThat(jwt2.getTokenValue()).isEqualTo(jwt2.getTokenValue());
    }


	@Test
    public void context2Loads() throws Exception {


        RSAKey rsaKey1 = JoseKeyGenerator.generateRsa();



        Path p1 = Paths.get("target/private_key.pem");
        Path p2 = Paths.get("target/public_key.pem");        

        CryptoKeyFiles.writeRSAPrivateKey(p1, rsaKey1.toKeyPair());
        CryptoKeyFiles.writeRSAPublicKey(p2, rsaKey1.toKeyPair());


        RSAPrivateKey privateKey = CryptoKeyFiles.readRSAPrivateKey(p1);
        RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(p2);


        RSAKey rsaKey2 = JoseKeyGenerator.generateRsa(publicKey, privateKey);


        Jwt jwt1 = JoseKeyEncryptor.encrypt(rsaKey2, (claims)->{
            claims.put("sub", "user1");
            claims.put("email", "user1");
            claims.put("name", "user1");            
        });
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(rsaKey2, () -> jwt1.getTokenValue());
        logger.info(jwt2);
        logger.info(jwt2.getTokenValue());

        Assertions.assertThat(jwt2.getTokenValue()).isEqualTo(jwt2.getTokenValue());
        

    }




}
