package io.u2ware.common.oauth2.jose;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class JoseKeyCodec {
    
    private JoseKeyCodec(){}

    /////////////////////////////////////////////////
    //
    /////////////////////////////////////////////////
    public static JWKSource<SecurityContext> source(RSAKey jwk) throws Exception{
        JWKSet jwkSet = new JWKSet(jwk);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
        return jwkSource;
    }

    public static JWKSet jwk(JWKSource<SecurityContext> jwkSource) throws Exception{
        JWKSelector jwkSelector = new JWKSelector((new JWKMatcher.Builder()).build());
        return new JWKSet(jwkSource.get(jwkSelector, (SecurityContext)null)); 
    }

    public static NimbusJwtEncoder encoder(JWKSource<SecurityContext> jwkSource)throws Exception{
        return new NimbusJwtEncoder(jwkSource);
    }

    public static NimbusJwtDecoder decoder(JWKSource<SecurityContext> jwkSource)throws Exception{

        Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
        jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgs.addAll(JWSAlgorithm.Family.EC);
        jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
        jwsAlgs.addAll(JWSAlgorithm.Family.SIGNATURE);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

        return new NimbusJwtDecoder(jwtProcessor);
    }


}
