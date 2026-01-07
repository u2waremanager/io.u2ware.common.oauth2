package io.u2ware.common.oauth2.jose;

import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

public class JoseKeyEncryptor {
    
    public static Jwt encrypt(JwtEncoder encoder, Consumer<Map<String, Object>> claimsConsumer){

        JwtClaimsSet claims = JwtClaimsSet.builder().claims(claimsConsumer).build();

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, claims);
        return encoder.encode(jwtEncoderParameters);
    }

    public static Jwt decrypt(JwtDecoder decoder, Supplier<String> value) throws Exception{
        String token = value.get();
        if ((token.toLowerCase().startsWith("Bearer".toLowerCase()))) {
            token = token.substring("Bearer".length()).trim();
        }
        return decoder.decode(token);
    }
}