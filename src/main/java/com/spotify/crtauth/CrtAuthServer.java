/*
 * Copyright (c) 2014 Spotify AB.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.spotify.crtauth;

import com.google.common.base.Charsets;
import com.google.common.base.Optional;
import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.TokenExpiredException;
import com.spotify.crtauth.keyprovider.KeyProvider;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.protocol.CrtAuthCodec;
import com.spotify.crtauth.protocol.Response;
import com.spotify.crtauth.protocol.Token;
import com.spotify.crtauth.utils.RealTimeSupplier;
import com.spotify.crtauth.utils.TimeSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.spotify.crtauth.ASCIICodec.decode;
import static com.spotify.crtauth.ASCIICodec.encode;

/**
 * Instances of this class implements the server part of an crtauth authentication interaction.
 * A consumer of this class would typically provide a means for remote clients to call the
 * createChallenge() and createToken() methods using i.e. HTTPS.
 *
 * A client is expected to perform the following operations:
 * <ol>
 *   <li>Request a challenge by obtaining the output from createChallenge(),
 *   given the username of the user about to authenticate.</li>
 *   <li>Turn the challenge string into a response string using a private key. One implementation
 *   of response generation is provided in CrtAuthClient.crateResponse()</li>
 *   <li>Return the response String to the server in exchange for a token string.</li>
 *   <li>Use the provided token to make authenticated API calls on the server. The API endpoints
 *   in turn use verifyToken() to check that the token provided is indeed valid.</li>
 * </ol>
 *
 * The authentication mechanism is time sensitive, since it relies on a specified validity period
 * for tokens. A clock can be off at most CLOCK_FUGDE seconds before the server starts emitting
 * too new/too old messages. Also, after the server sends a challenge, the client is supposed to
 * produce a reply within RESP_TIMEOUT seconds.
 */
public class CrtAuthServer {
  private static final UnsignedInteger CLOCK_FUDGE = UnsignedInteger.fromIntBits(2);
  private static final UnsignedInteger RESPONSE_TIMEOUT = UnsignedInteger.fromIntBits(20);
  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
  private final UnsignedInteger tokenLifetimeInS;
  private final String serverName;
  private final KeyProvider keyProvider;
  private final TimeSupplier timeSupplier;
  private final Random random;
  private final byte[] secret;

  private static final Logger log = LoggerFactory.getLogger(CrtAuthServer.class);

  public static class Builder {
    private static final UnsignedInteger DEFAULT_TOKEN_LIFETIME_IN_S =
        UnsignedInteger.fromIntBits(60);
    private static final TimeSupplier DEFAULT_TIME_SUPPLIER = new RealTimeSupplier();
    private Optional<UnsignedInteger> tokenLifetimeInS = Optional.absent();
    private String serverName;
    private KeyProvider keyProvider;
    private Optional<TimeSupplier> timeSupplier = Optional.absent();
    private Optional<Random> random = Optional.absent();
    private byte[] secret;

    public Builder setTokenLifetimeInS(int tokenLifetimeInS) {
      this.tokenLifetimeInS = Optional.of(UnsignedInteger.fromIntBits(tokenLifetimeInS));
      return this;
    }

    public Builder setServerName(String serverName) {
      this.serverName = serverName;
      return this;
    }

    public Builder setKeyProvider(KeyProvider keyProvider) {
      this.keyProvider = keyProvider;
      return this;
    }

    public Builder setTimeSupplier(TimeSupplier timeSupplier) {
      this.timeSupplier = Optional.of(timeSupplier);
      return this;
    }

    public Builder setRandom(Random random) {
      this.random = Optional.of(random);
      return this;
    }

    public Builder setSecret(byte[] secret) {
      checkArgument(secret.length > 0);
      this.secret = Arrays.copyOf(secret, secret.length);
      return this;
    }

    public CrtAuthServer build() {
      checkNotNull(serverName);
      checkNotNull(keyProvider);
      checkNotNull(secret);
      return new CrtAuthServer(tokenLifetimeInS.or(DEFAULT_TOKEN_LIFETIME_IN_S),
          serverName,
          keyProvider,
          timeSupplier.or(DEFAULT_TIME_SUPPLIER),
          random.or(new Random()),
          secret
      );
     }
  }

  private CrtAuthServer(UnsignedInteger tokenLifetimeInS, String serverName, KeyProvider keyProvider,
      TimeSupplier timeSupplier, Random random, byte[] secret) {
    this.tokenLifetimeInS = tokenLifetimeInS;
    this.serverName = serverName;
    this.keyProvider = keyProvider;
    this.timeSupplier = timeSupplier;
    this.random = random;
    checkArgument(secret != null && secret.length > 0);
    this.secret = Arrays.copyOf(secret, secret.length);
  }

  /**
   * Create a challenge to authenticate a given user. The userName needs to be provided at this
   * stage to encode a fingerprint of the public key stored in the server encoded in the challenge.
   * This is required because a client can hold more than one private key and would need this
   * information to pick the right key to sign the response. If the keyProvider fails to retrieve
   * the public key, a fake Fingerprint is generated so that the presence of a challenge doesn't
   * reveal whether a user key is present on the server or not.
   *
   * @param request The request message which contains an encoded username
   *
   * @return A challenge message.
   */
  public String createChallenge(String request) throws InvalidInputException {

    String userName;
    try {
      userName = CrtAuthCodec.deserializeRequest(request);
    } catch (DeserializationException e) {
      throw new InvalidInputException(e);
    }

    Fingerprint fingerprint;
    try {
      fingerprint = new Fingerprint(keyProvider.getKey(userName));
    } catch (KeyNotFoundException e) {
      log.info("No public key found for user {}, creating fake fingerprint", userName);
      fingerprint = createFakeFingerprint(userName);
    }

    byte[] uniqueData = new byte[Challenge.UNIQUE_DATA_LENGTH];
    UnsignedInteger timeNow = timeSupplier.getTime();
    random.nextBytes(uniqueData);
    Challenge challenge = Challenge.newBuilder()
        .setFingerprint(fingerprint)
        .setUniqueData(uniqueData)
        .setValidFromTimestamp(timeNow.minus(CLOCK_FUDGE))
        .setValidToTimestamp(timeNow.plus(RESPONSE_TIMEOUT))
        .setServerName(serverName)
        .setUserName(userName)
        .build();
    try {
      return encode(CrtAuthCodec.serialize(challenge, secret));
    } catch (SerializationException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Generate a fake real looking fingerprint for a nonexistant user.
   *
   * @param userName the username to seed the transform with
   * @return a Fingerprint with bytes that are a function of username and secret
   */
  private Fingerprint createFakeFingerprint(String userName) {
    byte[] usernameHmac = CrtAuthCodec.getAuthenticationCode(
        this.secret, userName.getBytes(Charsets.UTF_8));
    return new Fingerprint(Arrays.copyOfRange(usernameHmac, 0, 6));
  }

  /**
   * Given the response to a previous challenge, produce a token used by the client to authenticate.
   *
   * @param response The client's response to the initial challenge.
   * @return A token used to authenticate subsequent requests.
   * @throws InvalidInputException
   */
  public String createToken(String response) throws InvalidInputException {
    final Response decodedResponse;
    final Challenge challenge;
    try {
      decodedResponse = CrtAuthCodec.deserializeResponse(decode(response));
      challenge = CrtAuthCodec.deserializeChallengeAuthenticated(
          decodedResponse.getPayload(), secret);
    } catch (DeserializationException e) {
      throw new InvalidInputException(e);
    }

    if (!challenge.getServerName().equals(serverName)) {
      throw new InvalidInputException("Got challenge with the wrong server_name encoded.");
    }
    PublicKey publicKey;
    try {
      publicKey = keyProvider.getKey(challenge.getUserName());
    } catch (KeyNotFoundException e) {
      // If the user requesting authentication doesn't have a public key,  we throw an
      // InvalidInputException. This normally shouldn't happen, since at this stage a challenge
      // should have already been sent, which in turn requires knowledge of the user's public key.
      throw new InvalidInputException(e);
    }
    boolean signatureVerified = false;
    try {
      Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      signature.initVerify(publicKey);
      signature.update(decodedResponse.getPayload());
      signatureVerified = signature.verify(decodedResponse.getSignature());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    if (!signatureVerified) {
      throw new InvalidInputException("Client did not provide proof that it controls the secret " +
          "key.");
    }
    if (challenge.isExpired(timeSupplier)) {
      throw new InvalidInputException("The challenge is out of its validity period");
    }
    UnsignedInteger validFrom = timeSupplier.getTime().minus(CLOCK_FUDGE);
    UnsignedInteger validTo = timeSupplier.getTime().plus(tokenLifetimeInS);
    Token token = new Token(validFrom.intValue(), validTo.intValue(), challenge.getUserName());
    try {
      return encode(CrtAuthCodec.serialize(token, secret));
    } catch (SerializationException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Verify that a given token is valid, i.e. that it has been produced by the current
   * authenticator and that it's not outside of its validity period.
   *
   * @param token the token to validate.
   * @return the username that this token belongs to.
   * @throws InvalidInputException If the token appears to have been tampered with.
   * @throws TokenExpiredException If the token is outside of its validity period.
   */
  public String validateToken(String token) throws InvalidInputException, TokenExpiredException {
    final Token deserializedToken;
    try {
      deserializedToken = CrtAuthCodec.deserializeTokenAuthenticated(decode(token), secret);
    } catch (DeserializationException e) {
      throw new InvalidInputException(String.format("failed deserialize token '%s'", token));
    }
    deserializedToken.isExpired(timeSupplier);
    return deserializedToken.getUserName();
  }
}
