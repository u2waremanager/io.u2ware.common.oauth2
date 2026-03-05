package io.u2ware.common.oauth2.jwt;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;


public class JwtBuilder {
 
    public static JwtBuilder with(JwtEncoder jwtEncoder) {
        return new JwtBuilder(jwtEncoder);
    }

    private JwtEncoder jwtEncoder;
    private JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();


    private JwtBuilder(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public JwtBuilder claims(Consumer<Map<String, Object>> claimsConsumer) {
        claimsBuilder.claims(claimsConsumer);
        return this;
    }

    public Jwt build() {
        JwtClaimsSet claims = claimsBuilder.build();
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
    }

    // private String issuer(){
    //     try{
    //         return ServletUriComponentsBuilder.fromCurrentContextPath().toUriString();
    //     }catch(Exception e){
    //         return "u2ware-oauth2-server";
    //     }
    // }
}