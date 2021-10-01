/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.extension.oauthhmac.api;

import static java.lang.Thread.currentThread;
import static java.util.Objects.hash;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.initialiseIfNeeded;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.slf4j.LoggerFactory.getLogger;

import org.mule.api.annotation.NoExtend;
import org.mule.api.annotation.NoInstantiate;
import org.mule.extension.http.api.HttpResponseAttributes;
import org.mule.extension.http.api.request.authentication.HttpRequestAuthentication;
import org.mule.runtime.api.exception.DefaultMuleException;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.extension.api.annotation.Alias;
import org.mule.runtime.extension.api.annotation.param.Optional;
import org.mule.runtime.extension.api.annotation.param.Parameter;
import org.mule.runtime.extension.api.annotation.param.reference.ConfigReference;
import org.mule.runtime.extension.api.runtime.operation.Result;
import org.mule.runtime.extension.api.runtime.parameter.Literal;
import org.mule.runtime.extension.api.runtime.parameter.ParameterResolver;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.domain.message.request.HttpRequestBuilder;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.ServerNotFoundException;
import org.mule.runtime.http.api.client.auth.HttpAuthentication;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import org.mule.extension.oauthhmac.api.authentication.TokenBasedAuthentication;
import javax.inject.Inject;
import java.util.Random;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;


@Alias("oauth-1-hmac-token")
public class OAuthHMAC extends TokenBasedAuthentication {

  private static final Logger LOGGER = getLogger(OAuthHMAC.class);
  private static final String UTF_8 = "UTF-8";
  private static final String HMAC_SHA1 = "HmacSHA1";
  private static final String HMAC_SHA256 = "HmacSHA256";
  private final Random random;

  @Inject
  private HttpService httpService;

  public OAuthHMAC() {
    this.random = new Random();
  }

  @Override
  public boolean shouldRetry(final Result<Object, HttpResponseAttributes> firstAttemptResult) throws MuleException {
    return false;
  }

  @Override
  public void retryIfShould(Result<Object, HttpResponseAttributes> firstAttemptResult, Runnable retryCallback,
                            Runnable notRetryCallback) {
    notRetryCallback.run();
  }

  @Override
  public void authenticate(HttpRequestBuilder builder) throws MuleException {
    try {
      builder.addHeader(AUTHORIZATION, generateAuthHeader(builder));
    } catch (Exception e) {
      throw new DefaultMuleException(e.getCause());
    }
  }

  @Override
  public final void doInitialize() throws InitialisationException {

  }

  private String generateAuthHeader(HttpRequestBuilder builder) throws MuleException {
    final Long timestampLong = System.currentTimeMillis() / 1000L;
    final String timestamp = String.valueOf(timestampLong);
    final String nonce = String.valueOf(timestampLong + this.random.nextInt());
    final String macSignature = getSignatureAlgorithm().contains("256") ? "HmacSHA256" : "HmacSHA1";
    final String[] splittedUrl = (builder.getUri().toString().replace(":443", "")).split("\\?");
    final MultiMap<String, String> queryParams = builder.getQueryParams();
    final String decodedQP = parseQueryParams(queryParams);

    String signature;
    String encodedUrl;

    try {
      final TreeMap<String, String> paramsMap = new TreeMap<String, String>();
      paramsMap.put("oauth_consumer_key", this.getConsumerKey());
      paramsMap.put("oauth_nonce", nonce);
      paramsMap.put("oauth_signature_method", this.getSignatureAlgorithm());
      paramsMap.put("oauth_timestamp", timestamp);
      paramsMap.put("oauth_token", this.getTokenId());
      paramsMap.put("oauth_version", "1.0");
      final StringBuilder stringBuilder = new StringBuilder();
      for (final Map.Entry<String, String> entry2 : paramsMap.entrySet()) {
        if (stringBuilder.length() > 0) {
          stringBuilder.append("&");
        }
        stringBuilder.append(entry2.getKey());
        stringBuilder.append("=");
        stringBuilder.append(entry2.getValue());
      }

      if (queryParams.size() == 0) {
        encodedUrl =
            this.encode(builder.getMethod()) + "&" + this.encode(splittedUrl[0]) + "&" + this.encode(stringBuilder.toString());
      } else {
        encodedUrl = this.encode(builder.getMethod()) + "&" + this.encode(splittedUrl[0]) + "&" + this.encode(decodedQP + "&"
            + stringBuilder.toString());
      }

      final String macKey = this.encode(this.getConsumerSecret()) + "&" + this.encode(this.getTokenSecret());
      final String fullEncodedUrl = encodedUrl;
      final Mac mac = Mac.getInstance(macSignature);
      mac.init(new SecretKeySpec(macKey.getBytes(StandardCharsets.UTF_8), macSignature));
      final byte[] bytes = mac.doFinal(fullEncodedUrl.getBytes(StandardCharsets.UTF_8));
      signature = this.encode(new String(Base64.encodeBase64(bytes), StandardCharsets.UTF_8).replace("\r\n", ""));
    } catch (Exception ex2) {
      throw new DefaultMuleException(ex2.getCause());
    }
    return String.format(
                         "OAuth oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_token=\"%s\", oauth_consumer_key=\"%s\", oauth_timestamp=\"%s\", oauth_signature_method=\"%s\", oauth_version=\"1.0\", realm=\"%s\"",
                         nonce, signature, this.getTokenId(), this.getConsumerKey(), timestamp, this.getSignatureAlgorithm(),
                         this.getAccount());
  }

  private String encode(final String text) throws UnsupportedEncodingException {
    return URLEncoder.encode(text, "UTF-8");
  }

  private String parseQueryParams(MultiMap<String, String> qParams) throws MuleException {
    String parsedQP = "";

    try {
      int qpPosition = 0;

      for (String qpName : qParams.keySet()) {
        if (qpPosition > 0)
          parsedQP += "&";

        parsedQP += String.format("%s=%s", qpName.toString(), qParams.get(qpName).toString());
        qpPosition++;
      }
    } catch (Exception e) {
      throw new DefaultMuleException(e.getCause());
    }

    return parsedQP;
  }
}
