package org.keycloak.social.dingding.models;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class TokenRequest {
    public String clientId;
    public String clientSecret;
    public String code;
    public String refreshToken;
    public String grantType;
}
