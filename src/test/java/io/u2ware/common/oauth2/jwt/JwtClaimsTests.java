package io.u2ware.common.oauth2.jwt;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import io.u2ware.common.oauth2.jose.JoseKeyCodec;
import io.u2ware.common.oauth2.jose.JoseKeyEncryptor;
import io.u2ware.common.oauth2.jose.JoseKeyGenerator;

public class JwtClaimsTests {
    


	@Test
    public void context1Loads() throws Exception {

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());

        RSAKey key = JoseKeyGenerator.generateRsa();
        JWKSource<SecurityContext> jwkSource = JoseKeyCodec.source(key);
        JwtEncoder encoder = JoseKeyCodec.encoder(jwkSource);
        JwtDecoder decoder = JoseKeyCodec.decoder(jwkSource);


        Jwt jwt1 = JoseKeyEncryptor.encrypt(encoder, claims->{
            // claims.put("sub", "user01");
            // claims.put("email", "user01@example.com");
            // claims.put("name", "user01");



            claims.put(SimpleJwtClaims.jti.name(), UUID.randomUUID().toString());
            claims.put(SimpleJwtClaims.sub.name(), "user01");


            Instant iat = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            Instant exp = iat.plus(1, ChronoUnit.SECONDS);

            claims.put(SimpleJwtClaims.iat.name(), Date.from(iat));
            claims.put(SimpleJwtClaims.exp.name(), Date.from(exp));
        });
        System.out.println("jwt1: "+jwt1.getTokenValue());
        System.out.println("jwt1: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt1));

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault()); // Specify a time zone

        System.out.println("jwt1: "+formatter.format(jwt1.getIssuedAt()));
        System.out.println("jwt1: "+formatter.format(jwt1.getExpiresAt()));

        System.out.println(" "+formatter.format(LocalDateTime.now()));
        // Thread.sleep(1000*70); // Clock Skew. default 60 seconds. 1분 이상 기다려야 만료됨.
        System.out.println(" "+formatter.format(LocalDateTime.now()));

        Jwt jwt2 = JoseKeyEncryptor.decrypt(decoder, ()-> jwt1.getTokenValue());
        System.out.println("jwt2: "+jwt2.getTokenValue());
        System.out.println("jwt2: "+formatter.format(jwt2.getIssuedAt()));
        System.out.println("jwt2: "+formatter.format(jwt2.getExpiresAt()));

    //  OAuth2TokenValidator<Jwt> withClockSkew = new DelegatingOAuth2TokenValidator<>(
    //         new JwtTimestampValidator(Duration.ofSeconds(60)),
    //         new JwtIssuerValidator(issuerUri));
    //  jwtDecoder.setJwtValidator(withClockSkew);
        
        // System.out.println("jwt2: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt2));
    }

}
