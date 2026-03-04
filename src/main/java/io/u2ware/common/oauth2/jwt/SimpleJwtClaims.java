package io.u2ware.common.oauth2.jwt;

public enum SimpleJwtClaims {

    iss("(Issuer): 토큰 발급자. http://..."),
    sub("(Subject): 토큰 제목 (일반적으로 사용자 ID 등 고유 식별자)"),
    aud("(Audience): 토큰 수신자 http://..."),
    exp("(Expiration Time): 토큰 만료 시간 (NumericDate 형식)"),
    nbf("(Not Before): 토큰 활성 시작 시간 (이 시간 전에는 처리 불가)"),
    iat("(Issued At): 토큰 발급 시간"),
    jti("(JWT ID): JWT의 고유 식별자"),

    auth_time("[Authentication Time] 인증 시간 (사용자가 언제 실제 로그인(인증)을 했는가?)"),
    nonce("[Number used once] 1회성무작위 문자"),
    acr("[Authentication Context Class Reference] 인증 방식의 강도 (urn:mace:incommon:iap:silver, 2FA)"),
    amr("[Authentication Methods References] 인증 방법 ('pwd', 'opt')"),
    azp(" [Authorized party] 토큰 제출 대상 Oauth2 Resource Server (http://....)"),

    at_hash("[Access Token Hash] 액세스 토큰(access_token) 해시"),
    c_hash("[Access Code Hash] 인증 코드(code) 해시"),

    // Additional Claims
    provider(""),
    id(""),
    name(""),
    email(""),
    principal(""),
    authorities("")
    ;

    private String description;
    SimpleJwtClaims(String description){
        this.description = description;           
    }
    public String toString(){
        return name()+" "+description;
    }

}
