package io.u2ware.common.oauth2.crypto;

import java.nio.charset.StandardCharsets;
// import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class CryptoEncryptor {

    public static String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static String DEFAULT_IV = CryptoEncryptor.class.getName().substring(0, 16);

    public static String encrypt(String plainText, SecretKey secretKey) throws Exception{
        return encrypt(plainText, secretKey, DEFAULT_IV);
    }
    public static String encrypt(String plainText, SecretKey secretKey, String secretSpec) throws Exception{
        return encrypt(plainText, secretKey,  new IvParameterSpec(secretSpec.getBytes()));
    }
    public static String encrypt(String plainText, SecretKey secretKey, IvParameterSpec secretSpec) throws Exception{
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey,  secretSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(encrypted));        
    }


    public static String decrypt(String cipherText, SecretKey secretKey) throws Exception{
        return decrypt(cipherText, secretKey, DEFAULT_IV);
    }
    public static String decrypt(String cipherText, SecretKey secretKey, String secretSpec) throws Exception{
        return decrypt(cipherText, secretKey,  new IvParameterSpec(secretSpec.getBytes()));
    }
    public static String decrypt(String cipherText, SecretKey secretKey, IvParameterSpec secretSpec) throws Exception{
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, secretSpec); 
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, StandardCharsets.UTF_8);       
    }






    private SecretKey secretKey;
    private IvParameterSpec secretSpec;

    public CryptoEncryptor(SecretKey secretKey){
        this.secretKey = secretKey;
        // byte[] iv = new byte[16];
        // new SecureRandom().nextBytes(iv);
        // this.secretSpec = new IvParameterSpec(iv);
        this.secretSpec = new IvParameterSpec(getClass().getName().getBytes());
    }
    public CryptoEncryptor(SecretKey secretKey, String secretSpec){
        this.secretKey = secretKey;
        this.secretSpec = new IvParameterSpec(secretSpec.getBytes());
    }

    public String encrypt(String plainText) throws Exception {
        try{
            return CryptoEncryptor.encrypt(plainText, secretKey, secretSpec);
        }catch(Exception e){
            return null;
        }
    }

    public String decrypt(String cipherText) throws Exception {
        try{
            return CryptoEncryptor.decrypt(cipherText, secretKey, secretSpec);
        }catch(Exception e){
            return null;
        }
    }
}
