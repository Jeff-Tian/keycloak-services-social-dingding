/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.wechat;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class WechatWorkIdentityProviderFactory
    extends AbstractIdentityProviderFactory<WechatWorkIdentityProvider>
    implements SocialIdentityProviderFactory<WechatWorkIdentityProvider> {

  public static final String PROVIDER_ID = "wechat-work";

  @Override
  public String getName() {
    return "企业微信 WeCom";
  }

  @Override
  public WechatWorkIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new WechatWorkIdentityProvider(session, new WechatWorkProviderConfig(model));
  }

  @Override
  public IdentityProviderModel createConfig() {
    return new WechatWorkProviderConfig();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
            .property().name(WechatWorkIdentityProvider.OAUTH2_PARAMETER_AGENT_ID)
            .label("企业微信 Agent ID")
            .helpText("企业微信 Agent ID")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue("1000004")
            .add()

            .build();
  }
}
