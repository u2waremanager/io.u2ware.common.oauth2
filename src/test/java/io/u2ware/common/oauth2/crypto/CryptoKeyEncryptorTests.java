package io.u2ware.common.oauth2.crypto;

import java.security.KeyPair;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;

public class CryptoKeyEncryptorTests {
    
    private Log logger = LogFactory.getLog(getClass());


	@Test
    public void context1Loads() throws Exception {

		String encrypt1 = CryptoKeyEncryptor.encrypt("SHA-256", "helloworld");
		logger.info(encrypt1);


		String encrypt2 = CryptoKeyEncryptor.encrypt("SHA-256", "helloworld");
		logger.info(encrypt2);
    }


	@Test
    public void context2Loads() throws Exception {

		SecretKeySpec key = CryptoKeyGenerator.generateAes();


		String encrypt = CryptoKeyEncryptor.encrypt(key, "helloworld");
		logger.info(encrypt);


		String decrypt = CryptoKeyEncryptor.decrypt(key, encrypt);
		logger.info(decrypt);
    }

	@Test
    public void context3Loads() throws Exception {

		KeyPair key = CryptoKeyGenerator.generateRsa();

        /////////////////////////////
		String encrypt1 = CryptoKeyEncryptor.encrypt(key.getPublic(), "helloworld");
		logger.info(encrypt1);

		String encrypt2 = CryptoKeyEncryptor.encrypt(key.getPrivate(), "helloworld");
		logger.info(encrypt2);


        /////////////////////////////
        try{
            String decrypt1 = CryptoKeyEncryptor.decrypt(key.getPublic(), encrypt1);
            logger.info(decrypt1);        
        }catch(Exception e){
            logger.error(e.getMessage());
        }   
		String decrypt1 = CryptoKeyEncryptor.decrypt(key.getPrivate(), encrypt1);
		logger.info(decrypt1);        


        /////////////////////////////
        try{
            String decrypt2 = CryptoKeyEncryptor.decrypt(key.getPrivate(), encrypt2);
            logger.info(decrypt2);        
        }catch(Exception e){
            logger.error(e.getMessage());
        }   
		String decrypt2 = CryptoKeyEncryptor.decrypt(key.getPublic(), encrypt2);
		logger.info(decrypt2);   

    }
}
