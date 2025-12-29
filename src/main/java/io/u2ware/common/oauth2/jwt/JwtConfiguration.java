package io.u2ware.common.oauth2.jwt;

import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.ObjectUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.crypto.CryptoKeyFiles;
import io.u2ware.common.oauth2.jose.JWKCodec;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;

public class JwtConfiguration {


    public JwtConfiguration(OAuth2ResourceServerProperties properties) throws Exception{

        this.jwtProperties = properties.getJwt();

        Resource publicKeyLocation = jwtProperties.getPublicKeyLocation();
        String jwkSetUri = jwtProperties.getJwkSetUri();

        if(! ObjectUtils.isEmpty(publicKeyLocation)) {
            // logger.info("NimbusJwtDecoder by publicKeyLocation");
            Path path = Path.of(publicKeyLocation.getURI());
            RSAPublicKey publicKey = CryptoKeyFiles.readRSAPublicKey(path);
            this.jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
            return;
        }

        if(! ObjectUtils.isEmpty(jwkSetUri)) {
            this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
            return;
        }

        RSAKey key = JoseKeyGenerator.generateRsa();
        JWKSource<SecurityContext> jwtSource = JWKCodec.source(key);
        this.jwtEncoder = JWKCodec.encoder(jwtSource);
        this.jwtDecoder = JWKCodec.decoder(jwtSource);
        this.jwtDecoder = JWKCodec.decoder(jwtSource);
        this.jwkSet = JWKCodec.set(jwtSource);
    }


    private JwtDecoder jwtDecoder;
    private JwtEncoder jwtEncoder;
    private JWKSet jwkSet;
    private OAuth2ResourceServerProperties.Jwt jwtProperties;

    public JwtDecoder jwtDecoder() {
        return jwtDecoder;
    }

    public JwtEncoder jwtEncoder() {
        return jwtEncoder;
    }
    public JWKSet jwkSet() {
        return jwkSet;
    }
    public OAuth2ResourceServerProperties.Jwt jwtProperties() {
        return jwtProperties;
    }

    public JwtAuthenticationConverter jwtConverter(Converter<Jwt,Collection<GrantedAuthority>> customJwtGrantedAuthoritiesConverter) {

        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = null;
        if(customJwtGrantedAuthoritiesConverter == null) {
            JwtGrantedAuthoritiesConverter c = new JwtGrantedAuthoritiesConverter();
            c.setAuthoritiesClaimName("authorities");
            c.setAuthorityPrefix("");
            jwtGrantedAuthoritiesConverter = c;
        }else{
            jwtGrantedAuthoritiesConverter = customJwtGrantedAuthoritiesConverter;
        }

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;

    }












}
