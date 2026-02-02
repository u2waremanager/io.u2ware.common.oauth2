package io.u2ware.common.oauth2.jwt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JoseKeyCodec;
import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;

public class JwtExport {
    

    // private Log logger = LogFactory.getLog(getClass());



	@Test
    public void context1Loads() throws Exception {

        RSAKey rsaKey = JoseKeyGenerator.generateRsa();
        JWKSource<SecurityContext> jwkSource = JoseKeyCodec.source(rsaKey);
        JWKSet jwkSet = JoseKeyCodec.jwk(jwkSource);
        NimbusJwtEncoder encoder = JoseKeyCodec.encoder(jwkSource);
        // NimbusJwtDecoder decoder = JoseKeyCodec.decoder(jwkSource);


        System.out.println("1: "+jwkSet);
        System.out.println("2: "+jwkSet.toPublicJWKSet());
        System.out.println("3: "+jwkSet.getKeys().size());


        Path pem = Paths.get("target/public.pem");
        Path token = Paths.get("target/public.txt");
        CryptoKeyFiles.writeRSAPublicKey(pem, rsaKey.toKeyPair());
        System.out.println(Files.readString(pem));

        RSAKey rsaKey2 = (RSAKey)jwkSet.getKeys().get(0);
        Path pem2 = Paths.get("target/public2.pem");
        CryptoKeyFiles.writeRSAPublicKey(pem2, rsaKey2.toKeyPair());
        System.out.println(Files.readString(pem2));




        Files.writeString(token, "", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        for(int i=0; i<=5; i++) {

            final String username = "user0"+i;

            Jwt jwt = JoseKeyEncryptor.encrypt(encoder, (claims)->{
                claims.put("sub", username);
                claims.put("email", username);
                claims.put("name", username);            
            });

            Files.writeString(token, jwt.getTokenValue(), StandardOpenOption.APPEND);
            Files.writeString(token, "\n\n", StandardOpenOption.APPEND);
        }

        System.out.println(Files.readString(token));

    }

}
