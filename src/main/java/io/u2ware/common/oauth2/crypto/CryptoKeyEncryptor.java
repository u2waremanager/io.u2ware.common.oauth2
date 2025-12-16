package io.u2ware.common.oauth2.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.SecretKey;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.util.ObjectUtils;

public class CryptoKeyEncryptor {

    public static String encrypt(String algorithm, String plainText) throws Exception{
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] encrypted = digest.digest(plainText.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(encrypted));
    }

    public static String ALGORITHM_SHA256 = "SHA-256";
    public static String TRANSFORMATION_RSA = "RSA/ECB/PKCS1Padding";
    public static String TRANSFORMATION_AES = "AES/CBC/PKCS5Padding";

    private static String DEFAULT_IV = CryptoKeyEncryptor.class.getName().substring(0, 16);

    public static String encrypt(SecretKey secretKey, String plainText) throws Exception{
        return encrypt(cipher(TRANSFORMATION_AES, Cipher.ENCRYPT_MODE, secretKey, DEFAULT_IV), plainText);
    }

    public static String decrypt(SecretKey secretKey, String cipherText) throws Exception{
        return decrypt(cipher(TRANSFORMATION_AES, Cipher.DECRYPT_MODE, secretKey, DEFAULT_IV), cipherText);
    }


    public static String encrypt(PublicKey publicKey, String plainText) throws Exception{
        return encrypt(cipher(TRANSFORMATION_RSA, Cipher.ENCRYPT_MODE, publicKey), plainText);
    }
    public static String decrypt(PublicKey publicKey, String cipherText) throws Exception{
        return decrypt(cipher(TRANSFORMATION_RSA, Cipher.DECRYPT_MODE, publicKey), cipherText);
    }


    public static String encrypt(PrivateKey privateKey, String plainText) throws Exception{
        return encrypt(cipher(TRANSFORMATION_RSA, Cipher.ENCRYPT_MODE, privateKey), plainText);
    }
    public static String decrypt(PrivateKey privateKey, String cipherText) throws Exception{
        return decrypt(cipher(TRANSFORMATION_RSA, Cipher.DECRYPT_MODE, privateKey), cipherText);
    }


    private static Cipher cipher(String transformation, int mode, Key key, String... secretSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation); // Specify padding
        if(ObjectUtils.isEmpty(secretSpec)){
            cipher.init(mode, key); 
        }else{
            cipher.init(mode, key, new IvParameterSpec(secretSpec[0].getBytes())); 
        }
        return cipher;
    } 

    private static String encrypt(Cipher cipher, String plainText) throws Exception {
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(encrypted));
    }

    private static String decrypt(Cipher cipher, String cipherText) throws Exception{
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);       
    }
}
