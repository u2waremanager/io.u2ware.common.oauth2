package io.u2ware.common.oauth2.jose;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import io.u2ware.common.oauth2.crypto.CryptoKeyGenerator;

public class JoseKeyGenerator {

    public static OctetSequenceKey generateSha() {
        SecretKey secretKey = CryptoKeyGenerator.generateSha();
        // @formatter:off
        return new OctetSequenceKey.Builder(secretKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }    

    public static OctetSequenceKey generateAes() {
        SecretKey secretKey = CryptoKeyGenerator.generateAes();
        // @formatter:off
        return new OctetSequenceKey.Builder(secretKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }    


    public static RSAKey generateRsa() {
        return generateRsa(CryptoKeyGenerator.generateRsa());
    }

    public static RSAKey generateRsa(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // @formatter:off
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }

    public static RSAKey generateRsa(RSAPublicKey publicKey) {
        // @formatter:off
        return new RSAKey.Builder(publicKey)
                .build();
        // @formatter:on
    }
    public static RSAKey generateRsa(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        // @formatter:off
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();
        // @formatter:on
    }









    public static ECKey generateEc() {
        KeyPair keyPair = CryptoKeyGenerator.generateEc();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        Curve curve = Curve.forECParameterSpec(publicKey.getParams());
        // @formatter:off
        return new ECKey.Builder(curve, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on
    }



}
