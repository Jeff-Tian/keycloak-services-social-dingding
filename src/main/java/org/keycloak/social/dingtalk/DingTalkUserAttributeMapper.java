package org.keycloak.social.dingtalk;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** User attribute mapper. */
public class DingTalkUserAttributeMapper extends AbstractJsonUserAttributeMapper {
  private static final String PROFILE_MOBILE = DingTalkIdentityProvider.PROFILE_MOBILE;
  private static final String[] cp = new String[] {DingTalkIdentityProviderFactory.PROVIDER_ID};

  @Override
  public String[] getCompatibleProviders() {
    return cp;
  }

  @Override
  public String getId() {
    return "dingtalk-work-user-attribute-mapper";
  }

  @Override
  public void updateBrokeredUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    user.setSingleAttribute(PROFILE_MOBILE, context.getUserAttribute(PROFILE_MOBILE));
  }
}
