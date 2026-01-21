package io.u2ware.common.oauth2.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;


public enum JwtGenerators {

    google(new JwtGeneratorByGoogle()),

    naver(new JwtGeneratorByNaver()),

    kakao(new JwtGeneratorByKakao()),

    github(new JwtGeneratorByGithub()),

    apple(new JwtGeneratorByApple()),

    facebook(new JwtGeneratorByFacebook()),

    u2ware(new JwtGeneratorByU2ware()),

    ;




    private final JwtGenerator jwtGenerator;

    JwtGenerators(JwtGenerator jwtGenerator) {
        this.jwtGenerator = jwtGenerator;
    }

    public Jwt generate(JwtEncoder jwtEncoder, OAuth2AuthenticationToken token) {

        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        ServletRequestAttributes request = (ServletRequestAttributes)attrs;
        HttpServletRequest request1 = request.getRequest();
        String issuer = request1.getScheme()+"://"+request1.getServerName()+":"+request1.getServerPort();


        String registrationId = token.getAuthorizedClientRegistrationId();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .claims((c) -> {
                    extractClaims(c, token, registrationId);
                })
                .issuer(issuer)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60 * 60 * 24 * 30))
                .claim("nonce", registrationId)
                .id(token.getName())
                .build();
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
    }

    // "vmArgs": "--add-opens java.base/java.time=ALL-UNNAMED"


    private void extractClaims(Map<String, Object> claims, Authentication principal, String registrationId) {


        if (principal.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal.getPrincipal();
            OidcIdToken idToken = oidcUser.getIdToken();
            jwtGenerator.extractClaims(claims, idToken.getClaims(), registrationId);
        } else if (principal.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) principal.getPrincipal();
            jwtGenerator.extractClaims(claims, oauth2User.getAttributes(), registrationId);
        } else {
            claims.putAll(Collections.emptyMap());
        }
    }


    public static JwtGenerators of(String value){

        try{
            return JwtGenerators.valueOf(value);
        }catch(Exception e){
            return JwtGenerators.u2ware;
        }
    }
}
