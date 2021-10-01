/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.extension.oauthhmac;

import org.mule.extension.http.api.request.authentication.HttpRequestAuthentication;
import org.mule.extension.http.api.request.proxy.HttpProxyConfig;
import org.mule.extension.oauthhmac.api.OAuthHMAC;
import org.mule.extension.oauthhmac.api.exception.OAuthClientErrors;
import org.mule.extension.oauthhmac.api.authentication.TokenBasedAuthentication;
import org.mule.runtime.extension.api.annotation.Extension;
import org.mule.runtime.extension.api.annotation.Import;
import org.mule.runtime.extension.api.annotation.Operations;
import org.mule.runtime.extension.api.annotation.SubTypeMapping;
import org.mule.runtime.extension.api.annotation.dsl.xml.Xml;
import org.mule.runtime.extension.api.annotation.error.ErrorTypes;

/**
 * An extension to hook oauth hmac to http extension connectors.
 *
 * @since 1.0
 */
@Extension(name = "OAuth 1.0 HMAC")
@Import(type = HttpRequestAuthentication.class)
@Import(type = HttpProxyConfig.class)
@SubTypeMapping(baseType = HttpRequestAuthentication.class,
    subTypes = {OAuthHMAC.class})
@ErrorTypes(OAuthClientErrors.class)
@Xml(prefix = "oauth-hmac")
public class OAuthHMACExtension {

}
