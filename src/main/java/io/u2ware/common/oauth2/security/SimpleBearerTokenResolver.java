package io.u2ware.common.oauth2.security;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import jakarta.servlet.http.HttpServletRequest;

public class SimpleBearerTokenResolver implements BearerTokenResolver {

    private DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();

    public SimpleBearerTokenResolver(OAuth2ResourceServerProperties properties) {
        if (OAuth2ResourceServerSupport.available(properties)) {
            delegate.setAllowUriQueryParameter(true); // ?access_token GET only
        } else {
            delegate.setAllowUriQueryParameter(false);
            delegate.setBearerTokenHeaderName("oops");
        }
    }

    @Override
    public String resolve(HttpServletRequest request) {
        return delegate.resolve(request);
    }

}
