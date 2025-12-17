package io.u2ware.common.oauth2.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jose.jwk.RSAKey;

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

        Jwt jwt1 = JoseKeyEncryptor.encrypt(key, claims("user1"));
        logger.info(jwt1);
        logger.info(jwt1.getTokenValue());


        Jwt jwt2 = JoseKeyEncryptor.decrypt(key, () -> jwt1.getTokenValue());
        logger.info(jwt2);
        logger.info(jwt2.getTokenValue());
    }

	@Test
    public void context2Loads() throws Exception {

        RSAKey key1 = JoseKeyGenerator.generateRsa();
        RSAKey key2 = JoseKeyGenerator.generateRsa();

        Jwt t1 = JoseKeyEncryptor.encrypt(key1, claims("user1"));
        logger.info(t1);
        logger.info(t1.getTokenValue());

        try{
            Jwt t2 = JoseKeyEncryptor.decrypt(key2, () -> t1.getTokenValue());
            logger.info(t2);
            logger.info(t2.getTokenValue());

        }catch(Exception e){
            logger.info(e.getMessage());
            assertThat(e).isNotNull();
        }
    }


}