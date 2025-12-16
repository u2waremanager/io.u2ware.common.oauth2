package io.u2ware.common.oauth2.crypto;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.RSAKey;

public class JoseKeyGeneratorTests {
 
    private Log logger = LogFactory.getLog(getClass());
    

    @Test   
    public void contextLoad() throws Exception {

        KeyPair keyPair1 = CryptoKeyGenerator.generateRsa();

        String encrypted = CryptoKeyEncryptor.encrypt(keyPair1.getPrivate(), "hello world");
        logger.info("encrypted: " + encrypted);

        RSAKey rsaKey2 = JoseKeyGenerator.generateRsa(keyPair1);
        String decrypted2 = CryptoKeyEncryptor.decrypt(rsaKey2.toRSAPublicKey(), encrypted);
        logger.info("decrypted: " + decrypted2);


        RSAKey rsaKey3 = JoseKeyGenerator.generateRsa((RSAPublicKey)keyPair1.getPublic());
        String decrypted3 = CryptoKeyEncryptor.decrypt(rsaKey3.toRSAPublicKey(), encrypted);
        logger.info("decrypted: " + decrypted3);


        try {
            CryptoKeyEncryptor.encrypt(rsaKey3.toRSAPrivateKey(), "1111");
        } catch (Exception e) {
            logger.info("decrypted error: " + e.getMessage());
        }
    }
}
