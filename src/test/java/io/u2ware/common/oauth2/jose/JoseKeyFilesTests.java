package io.u2ware.common.oauth2.jose;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import ch.qos.logback.classic.Logger;
import io.u2ware.common.oauth2.crypto.CryptoKeyEncryptor;
import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;

public class JoseKeyFilesTests {
    
    private Log logger = LogFactory.getLog(getClass());

// private static final Logger log = LoggerFactory.getLogger(LogSample.class);

    // private final Logger logger = Logger.g;//LoggerFactory.getLogger(this.getClass());



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

        JWKSource<SecurityContext> jwkSource1 = JoseKeyCodec.source(rsaKey1);
        NimbusJwtEncoder encoder1 = JoseKeyCodec.encoder(jwkSource1);
        // NimbusJwtDecoder decoder1 = JoseKeyCodec.decoder(jwkSource1);

        
        JWKSource<SecurityContext> jwkSource2 = JoseKeyCodec.source(rsaKey2);
        // NimbusJwtEncoder encoder2 = JoseKeyCodec.encoder(jwkSource2);
        NimbusJwtDecoder decoder2 = JoseKeyCodec.decoder(jwkSource2);

       


        Jwt jwt1 = JoseKeyEncryptor.encrypt(encoder1, (claims)->{
            claims.put("sub", "user1");
            claims.put("email", "user1");
            claims.put("name", "user1");            
        });
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(decoder2, () -> jwt1.getTokenValue());
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

        JWKSource<SecurityContext> jwkSource2 = JoseKeyCodec.source(rsaKey2);
        NimbusJwtEncoder encoder2 = JoseKeyCodec.encoder(jwkSource2);
        NimbusJwtDecoder decoder2 = JoseKeyCodec.decoder(jwkSource2);



        Jwt jwt1 = JoseKeyEncryptor.encrypt(encoder2, (claims)->{
            claims.put("sub", "user1");
            claims.put("email", "user1");
            claims.put("name", "user1");            
        });
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(decoder2, () -> jwt1.getTokenValue());
        logger.info(jwt2);
        logger.info(jwt2.getTokenValue());

        Assertions.assertThat(jwt2.getTokenValue()).isEqualTo(jwt2.getTokenValue());
        

    }

	@Test
    public void context3Loads() throws Exception {

        RSAKey rsaKey = JoseKeyGenerator.generateRsa();

        Path p1 = Paths.get("target/key1.json");
        Path p2 = Paths.get("target/key1.json");
        JoseKeyFiles.writeRSAPrivateKey(p1, rsaKey);
        JoseKeyFiles.writeRSAPublicKey(p2, rsaKey);


        // org.springframework.boot.logging.logback

        // RSAKey rsaKey11 = JoseKeyFiles.readRSAPrivateKey(p1);
        // RSAKey rsaKey12 = JoseKeyFiles.readRSAPublicKey(p1);

        // RSAKey rsaKey21 = JoseKeyFiles.readRSAPrivateKey(p2);
        // RSAKey rsaKey22 = JoseKeyFiles.readRSAPublicKey(p2);




        PrivateKey pri = rsaKey.toPrivateKey();
        PublicKey pub = rsaKey.toPublicKey();

        // String encrypted1 = CryptoKeyEncryptor.encrypt(pri, "hello world");
        // logger.info(encrypted1);

        // String decrypted1 = CryptoKeyEncryptor.decrypt(pub, encrypted1);
        // logger.info(decrypted1);



        // String encrypted2 = CryptoKeyEncryptor.encrypt(pub, "hello world22");
        // logger.info(encrypted2);

        // String decrypted2 = CryptoKeyEncryptor.decrypt(pri, encrypted2);
        // logger.info(decrypted2);


        // assertThat(true, JoseKeyCodec.source(rsaKey11));
        // assertThat(true, JoseKeyCodec.source(rsaKey12));
        // assertThat(false, JoseKeyCodec.source(rsaKey21));
    }



    private void assertThat(boolean actual, JWKSource<SecurityContext> jwkSource) throws Exception{

        try{
            NimbusJwtEncoder encoder = JoseKeyCodec.encoder(jwkSource);
            NimbusJwtDecoder decoder = JoseKeyCodec.decoder(jwkSource);


            Jwt jwt1 = JoseKeyEncryptor.encrypt(encoder, (claims)->{claims.put("hello", "world");});
            logger.info(jwt1);
            logger.info(jwt1.getTokenValue());


            Jwt jwt2 = JoseKeyEncryptor.decrypt(decoder, () -> jwt1.getTokenValue());
            logger.info(jwt2);
            logger.info(jwt2.getTokenValue());

            Assertions.assertThat(jwt2.getTokenValue()).isEqualTo(jwt2.getTokenValue());

        }catch(Exception e) {
            e.printStackTrace();
            Assertions.assertThat(false);
        }
    }


	// @Test
    // public void context4Loads() throws Exception {

    //     RSAKey rsaKey = JoseKeyGenerator.generateRsa();
    //     String a = create(rsaKey);
    //     logger.info(a);

    //     boolean valid = isValid(rsaKey, a);
    //     logger.info(valid);
    // }


    // public String create(RSAKey rsaKey) throws Exception {
    //     String orginLicense = rsaKey.toJSONObject().get("kid").toString();

    //     // KeyPair keyPair = rsaKey.toKeyPair();
    //     // PrivateKey privateKey = rsaKey.toPrivateKey();
    //     PublicKey publicKey = rsaKey.toPublicKey();
        
    //     String encryptedLicense = CryptoKeyEncryptor.encrypt(publicKey, orginLicense);
    //     return encryptedLicense;
    // }

    // public boolean isValid(RSAKey rsaKey,String encryptedLicense) throws Exception {
    //     try{
    //         String orginLicense = rsaKey.toJSONObject().get("kid").toString();

    //         // KeyPair keyPair = rsaKey.toKeyPair();
    //         PrivateKey privateKey = rsaKey.toPrivateKey();
    //         // PublicKey publicKey = rsaKey.toPublicKey();

    //         String decryptedLicense = CryptoKeyEncryptor.decrypt(privateKey, encryptedLicense);
    //         return decryptedLicense.equals(orginLicense.toString());

    //     }catch(Exception e){
    //         return false;
    //     }
    // }


}
