package org.keycloak.social.dingding;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class DingDingProviderConfig extends OAuth2IdentityProviderConfig {

  public DingDingProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public DingDingProviderConfig() {
    super();
  }
}
