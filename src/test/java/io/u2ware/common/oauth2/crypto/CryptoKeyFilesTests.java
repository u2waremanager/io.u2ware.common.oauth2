package io.u2ware.common.oauth2.crypto;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;

public class CryptoKeyFilesTests {
    
    private Log logger = LogFactory.getLog(getClass());

	@Test
    public void context1Loads() throws Exception {

		// String encrypt1 = CryptoKeyCodec.encrypt("SHA-256", "helloworld");
		// logger.info(encrypt1);


		// String encrypt2 = CryptoKeyCodec.encrypt("SHA-256", "helloworld");
		// logger.info(encrypt2);
    }


	@Test
    public void context2Loads() throws Exception {

		SecretKeySpec key1 = CryptoKeyGenerator.generateAes();


		String encrypt1 = CryptoKeyEncryptor.encrypt(key1, "helloworld");
		logger.info(encrypt1);

        Path path = Path.of("target/secretKey.key2");
        CryptoKeyFiles.writeAESKey(path, key1);

        SecretKeySpec key2 = CryptoKeyFiles.readAESKey(path);
		String decrypt2 = CryptoKeyEncryptor.decrypt(key2, encrypt1);
		logger.info(decrypt2);


		SecretKeySpec key3 = CryptoKeyGenerator.generateAes();
		try{
			String decrypt = CryptoKeyEncryptor.decrypt(key3, encrypt1);
			logger.info(decrypt);		

		}catch(Exception e){
			logger.info(e.getMessage());		
		}
    }


	@Test
    public void context3Loads() throws Exception {

		KeyPair key = CryptoKeyGenerator.generateRsa();

        Path path1 = Path.of("target/secretKey.pem");
        Path path2 = Path.of("target/secretKey");

		CryptoKeyFiles.writeRSAPublicKey(path1, key);
		CryptoKeyFiles.writeRSAPrivateKey(path2, key);

		RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path1);
		RSAPrivateKey privateKey = CryptoKeyFiles.readRSAPrivateKey(path2);


		String encrypt1 = CryptoKeyEncryptor.encrypt(publicKey, "helloworld");
		logger.info(encrypt1);

		String encrypt2 = CryptoKeyEncryptor.encrypt(privateKey, "helloworld");
		logger.info(encrypt2);


        /////////////////////////////
        try{
            String decrypt1 = CryptoKeyEncryptor.decrypt(publicKey, encrypt1);
            logger.info(decrypt1);        
        }catch(Exception e){
            logger.error(e.getMessage());
        }   
		String decrypt1 = CryptoKeyEncryptor.decrypt(privateKey, encrypt1);
		logger.info(decrypt1);       		


        /////////////////////////////
		String decrypt2 = CryptoKeyEncryptor.decrypt(publicKey, encrypt2);
		logger.info(decrypt2);   

        try{
            String decrypt22 = CryptoKeyEncryptor.decrypt(privateKey, encrypt2);
            logger.info(decrypt22);        
        }catch(Exception e){
            logger.error(e.getMessage());
        }   

	}
	
}
