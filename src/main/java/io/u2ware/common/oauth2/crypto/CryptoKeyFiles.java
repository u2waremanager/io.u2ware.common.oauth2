package io.u2ware.common.oauth2.crypto;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.converter.RsaKeyConverters;

public class CryptoKeyFiles {

    private static Converter<byte[],RSAPublicKey> rsaPublicKeyConverter = new Converter<byte[],RSAPublicKey>() {
        @Override
        @Nullable
        public RSAPublicKey convert(byte[] pem) {
            return RsaKeyConverters.x509().convert(new ByteArrayInputStream(pem));
        }
    };

    private static Converter<byte[],RSAPrivateKey> rsaPrivateKeyConverter = new Converter<byte[],RSAPrivateKey>() {
        @Override
        @Nullable
        public RSAPrivateKey convert(byte[] pem) {
            return RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(pem));
        }
    };


    private static Converter<byte[], String> base64Converter = new Converter<byte[],String>() {
        @Override
        @Nullable
        public String convert(byte[] bytes) {
            StringWriter sw = new StringWriter();
            PrintWriter writer =  new PrintWriter(sw);

            String base64Key = Base64.getEncoder().encodeToString(bytes);
            int lineLength = 64;
            for (int i = 0; i < base64Key.length(); i += lineLength) {
                int end = Math.min(i + lineLength, base64Key.length());
                writer.println(base64Key.substring(i, end));
            }
            writer.flush();
            return sw.toString();
        }
    };





    public static RSAPublicKey readRSAPublicKey(Path path) throws Exception{
        byte[] bytes = Files.readAllBytes(path);
        return rsaPublicKeyConverter.convert(bytes);
    }
    public static Path writeRSAPublicKey(Path path, KeyPair key) throws Exception{
        String keyString = base64Converter.convert(key.getPublic().getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        sb.append(keyString);
        sb.append("-----END PUBLIC KEY-----\n");
        return Files.writeString(path, sb);
    }

    public static RSAPrivateKey readRSAPrivateKey(Path path) throws Exception{
        byte[] bytes = Files.readAllBytes(path);
        return rsaPrivateKeyConverter.convert(bytes);
    }
    public static Path writeRSAPrivateKey(Path path, KeyPair key) throws Exception{
        String keyString = base64Converter.convert(key.getPrivate().getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        sb.append(keyString);
        sb.append("-----END PRIVATE KEY-----\n");
        return Files.writeString(path, sb);
    }


    public static Path writeAESKey(Path path, SecretKeySpec key) throws Exception{
        return Files.write(path, key.getEncoded());    
    }

    public static SecretKeySpec readAESKey(Path path) throws Exception{
        byte[] keyAsByte = Files.readAllBytes(path);
        return new SecretKeySpec(keyAsByte, "AES");
    }


    //////////////////////////////
    // KeyStore
    //////////////////////////////
    // public static Path store(Path path, SecretKey key, String password) throws Exception{

    //     char[] passwordAsChars = password.toCharArray();
    //     KeyStore keystore = KeyStore.getInstance("JCEKS");
    //     keystore.load(null, passwordAsChars);

    //     KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
    //     KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(passwordAsChars);
    //     keystore.setEntry(password, entry, param);
    //     keystore.store(Files.newOutputStream(path), passwordAsChars);

    //     return path;
    // }

    // public static SecretKey load(Path path, String algorithm, String password) throws Exception{
    //     char[] passwordAsChars = password.toCharArray();
    //     KeyStore keystore = KeyStore.getInstance("JCEKS");
    //     keystore.load(Files.newInputStream(path), passwordAsChars);
    //     return (SecretKeySpec) keystore.getKey(password, passwordAsChars);
    // }
}
