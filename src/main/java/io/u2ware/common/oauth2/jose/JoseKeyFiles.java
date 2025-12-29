package io.u2ware.common.oauth2.jose;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;

public class JoseKeyFiles {

    private static ObjectMapper objectMapper = new ObjectMapper();

    public static RSAKey readRSAPublicKey(Path path) throws Exception{
        String keyString = Files.readString(path);
        return RSAKey.parse(keyString);
    }
    public static Path writeRSAPublicKey(Path path, RSAKey key) throws Exception{
        Map<String,Object> keyMap = key.toPublicJWK().toJSONObject();
        String keyString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(keyMap);        
        return Files.writeString(path, keyString);
    }

    public static RSAKey readRSAPrivateKey(Path path) throws Exception{
        String keyString = Files.readString(path);
        return RSAKey.parse(keyString);
    }
    public static Path writeRSAPrivateKey(Path path, RSAKey key) throws Exception{
        Map<String,Object> keyMap = key.toJSONObject();
        String keyString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(keyMap);        
        return Files.writeString(path, keyString);
    }
}
