package io.u2ware.common.oauth2.crypto;

import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public class JoseKeyEncryptor {
    
    public static Jwt encrypt(RSAKey rsaKey, Consumer<Map<String, Object>> claimsConsumer){
        JWKSet jwkSet = new JWKSet(rsaKey);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtClaimsSet claims = JwtClaimsSet.builder().claims(claimsConsumer).build();
        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, claims);
        return encoder.encode(jwtEncoderParameters);
    }

    public static Jwt decrypt(RSAKey rsaKey, Supplier<String> value) throws Exception{
        String token = value.get();
        if ((token.toLowerCase().startsWith("Bearer".toLowerCase()))) {
            token = token.substring("Bearer".length()).trim();
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
       return decoder.decode(token);
    }
}