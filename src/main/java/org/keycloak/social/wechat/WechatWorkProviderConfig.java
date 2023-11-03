package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WechatWorkProviderConfig extends OAuth2IdentityProviderConfig {

  public WechatWorkProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public WechatWorkProviderConfig() {
    super();
  }

  public String getAgentId() {
    return getConfig().get(WechatWorkIdentityProvider.OAUTH2_PARAMETER_AGENT_ID);
  }

  public void setAgentId(String agentId) {
    getConfig().put(WechatWorkIdentityProvider.OAUTH2_PARAMETER_AGENT_ID, agentId);
  }

  public String getQrcodeAuthorizationUrl() {
    return getConfig().get("qrcodeAuthorizationUrl");
  }

  public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
    getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
  }
}
