package io.u2ware.common.oauth2.crypto;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;


public class JoseEncryptor {

    private NimbusJwtEncoder encoder;
    private NimbusJwtDecoder decoder;

    public JoseEncryptor(JWK jwk) {
        JWKSet jwkSet = new JWKSet(jwk);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        jwsAlgs.addAll(JWSAlgorithm.Family.SIGNATURE);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });

        this.encoder = new NimbusJwtEncoder(jwkSource);
        this.decoder = new NimbusJwtDecoder(jwtProcessor);

    }

    public JwtEncoder encoder() {
        return encoder;
    }

    public JwtDecoder decoder() {
        return decoder;
    }



    public JoseEncryptor(NimbusJwtDecoder decoder, NimbusJwtEncoder encoder) {
        this.decoder = decoder;
        this.encoder = encoder;
    }

    public Jwt encrypt(Consumer<Map<String, Object>> claimsConsumer) throws Exception {
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtClaimsSet claims = JwtClaimsSet.builder().claims(claimsConsumer).build();
        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, claims);
        return encoder.encode(jwtEncoderParameters);
    }

    public Jwt decrypt(Supplier<String> value) throws Exception {
        String token = value.get();
        if ((token.toLowerCase().startsWith("Bearer".toLowerCase()))) {
            token = token.substring("Bearer".length()).trim();
        }
        return decoder.decode(token);
    }

    //////////////////////////
    //
    //////////////////////////
    private static JoseEncryptor instance;
   
    public static JoseEncryptor getInstance() throws Exception{
        if(instance == null) {
            instance = new JoseEncryptor(JoseKeyGenerator.generateRsa());
        }
        return instance;
    }

    public static Boolean unavailable() {
        return instance == null;
    }


}
