package io.u2ware.common.oauth2.crypto;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
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

public class JoseKeyCodec {

    private JWK jwk;
    private NimbusJwtEncoder encoder;
    private NimbusJwtDecoder decoder;

    public JoseKeyCodec(JWK jwk) {
        this.jwk = jwk;
        JWKSet jwkSet = new JWKSet(jwk);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
        // JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

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

    public JoseKeyCodec(NimbusJwtDecoder decoder, NimbusJwtEncoder encoder) {
        this.decoder = decoder;
        this.encoder = encoder;
    }

    public JWK jwk() {
        return jwk;
    }

    public JwtEncoder encoder() {
        return encoder;
    }

    public JwtDecoder decoder() {
        return decoder;
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
}
