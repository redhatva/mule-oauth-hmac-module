/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.extension.oauthhmac.api.authentication;

import org.mule.extension.http.api.request.authentication.HttpRequestAuthentication;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.extension.api.annotation.param.Parameter;
import org.mule.runtime.extension.api.annotation.param.Optional;
import org.mule.runtime.extension.api.annotation.param.display.Placement;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;
import org.mule.runtime.extension.api.annotation.param.display.Password;

public abstract class TokenBasedAuthentication implements HttpRequestAuthentication, Lifecycle {

  protected void doInitialize() throws InitialisationException {

  }

  @Override
  public final void initialise() throws InitialisationException {

  }

  @Override
  public final void start() throws MuleException {

  }

  @Override
  public final void stop() throws MuleException {

  }

  @Override
  public final void dispose() {

  }

  @Parameter
  @DisplayName("Consumer Key")
  @Password
  @Placement(order = 1)
  private String consumerKey;

  @Parameter
  @DisplayName("Consumer Secret")
  @Password
  @Placement(order = 2)
  private String consumerSecret;

  @Parameter
  @DisplayName("Token ID")
  @Password
  @Placement(order = 3)
  private String tokenId;

  @Parameter
  @DisplayName("Token Secret")
  @Password
  @Placement(order = 4)
  private String tokenSecret;

  @Parameter
  @Placement(order = 5)
  private String account;

  @Parameter
  @Optional(defaultValue = "HMAC-SHA256")
  @Placement(order = 16)
  private String signatureAlgorithm;

  public String getConsumerKey() {
    return consumerKey;
  }

  public String getConsumerSecret() {
    return consumerSecret;
  }

  public String getTokenId() {
    return tokenId;
  }

  public String getTokenSecret() {
    return tokenSecret;
  }

  public String getAccount() {
    return account;
  }

  public String getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

}
