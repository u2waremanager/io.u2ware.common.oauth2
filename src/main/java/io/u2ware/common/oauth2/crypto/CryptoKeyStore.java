package io.u2ware.common.oauth2.crypto;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoKeyStore {

    public static Path save(Path path, SecretKey key) {
        try {
            byte[] keyAsByte = key.getEncoded();
            Files.copy(new ByteArrayInputStream(keyAsByte), path, StandardCopyOption.REPLACE_EXISTING);
            return path;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey load(Path path, String algorithm) {
        try {
            byte[] keyAsByte = Files.readAllBytes(path);
            return new SecretKeySpec(keyAsByte, algorithm);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Path save(Path path, SecretKey key, String password) {
        try {
            char[] passwordAsChars = password.toCharArray();
            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(null, passwordAsChars);

            KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
            KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(passwordAsChars);
            keystore.setEntry(password, entry, param);

            keystore.store(Files.newOutputStream(path), passwordAsChars);

            return path;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey load(Path path, String algorithm, String password) {
        try {
            char[] passwordAsChars = password.toCharArray();
            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(Files.newInputStream(path), passwordAsChars);

            return (SecretKeySpec) keystore.getKey(password, passwordAsChars);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
