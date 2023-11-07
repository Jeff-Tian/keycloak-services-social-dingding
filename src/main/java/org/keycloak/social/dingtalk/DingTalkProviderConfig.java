package org.keycloak.social.dingtalk;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class DingTalkProviderConfig extends OAuth2IdentityProviderConfig {

  public DingTalkProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public DingTalkProviderConfig() {
    super();
  }
}
