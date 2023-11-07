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

  public String getAgentId() {
    return getConfig().get(DingTalkIdentityProvider.OAUTH2_PARAMETER_AGENT_ID);
  }

  public void setAgentId(String agentId) {
    getConfig().put(DingTalkIdentityProvider.OAUTH2_PARAMETER_AGENT_ID, agentId);
  }

  public String getQrcodeAuthorizationUrl() {
    return getConfig().get("qrcodeAuthorizationUrl");
  }

  public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
    getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
  }
}
