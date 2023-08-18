package org.example.federation;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * 自定义鉴权成功处理器
 */
public class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {};

    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OidcUser) {
                this.oidcUserHandler.accept((OidcUser) authentication.getPrincipal());
            } else if (authentication.getPrincipal() instanceof OAuth2User) {
                this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
            }
        }

        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
