package io.u2ware.common.oauth2.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * 단방향 알고리즘의 경우 평문을 암호문으로 암호화할 수 있지만, 반대로 암호문을 평문으로 되돌리는 복호화는 불가능하다.
 * 보통 해시(Hash) 기법을 사용하며 SHA-256, MD-5등이 있다.
 * One Way Algorithm Key , One Way Encryption
 * 
 * 비대칭키 알고리즘은 암호화와 복호화에 사용되는 키가 서로 다르다.
 * 두 개의 키 중에서 하나는 반드시 공개되어야 사용이 가능하기 때문에 공개키 방식이라고도 한다.
 * 대표적으로는 RSA가 있다.
 * Asymmetric Key Encryption" 또는 "Public-key Encryption"
 * 
 * 
 * 대칭키 알고리즘은 암호화할 때 사용되는 키와 복호화할 때 사용되는 키가 동일한 암호화 방법을 말한다.
 * 가장 보편적으로 사용되는 알고리즘으로 AES가 있다.
 * "Symmetric Key Algorithm" 또는 "Symmetric-key cryptography"
 * 
 * encryp
 * encryption
 * encryptor
 * 
 * 
 */

public class CryptoKeyGenerator {

    //One Way Encryption
    public static SecretKey generateSha() {
        SecretKey hmacKey;
        try {
            hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return hmacKey;
    }


    //Symmetric Key Encryption
    public static SecretKeySpec generateAes() {
        SecretKeySpec aesKey;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey aes = keyGenerator.generateKey();
            aesKey = new SecretKeySpec(aes.getEncoded(), "AES");
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return aesKey;
    }











    //Asymmetric Key Encryption Or Public Key Algorithm
    public static KeyPair generateRsa() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    //Asymmetric Key Encryption Or Public Key Algorithm
    public static KeyPair generateEc() {
        EllipticCurve ellipticCurve = new EllipticCurve(
                new ECFieldFp(
                        new BigInteger(
                                "115792089210356248762697446949407573530086143415290314195533631308867097853951")),
                new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
        ECPoint ecPoint = new ECPoint(
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ellipticCurve,
                ecPoint,
                new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                1);

        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(ecParameterSpec);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

}
