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

import com.google.common.base.Optional;
import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.digest.DigestAlgorithm;
import com.spotify.crtauth.digest.VerifiableDigestAlgorithm;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.TokenExpiredException;
import com.spotify.crtauth.keyprovider.KeyProvider;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.protocol.Response;
import com.spotify.crtauth.protocol.Token;
import com.spotify.crtauth.protocol.VerifiableMessage;
import com.spotify.crtauth.utils.PublicKeys;
import com.spotify.crtauth.utils.RealTimeSupplier;
import com.spotify.crtauth.utils.TimeSupplier;

import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * This class implements the server-side methods used for authentication. Note that there is no
 * middleware layer that takes care of communication. In order to be able to authenticate a
 * remote client, a middleware layer wrapping the {@CrtAuthServer} class has to be implemented
 * separately.
 * The authentication mechanism is time sensitive, since it relies on a specified validity period
 * for tokens. A clock can be off at most CLOCK_FUGDE seconds before the server starts getting
 * too new/too old messages. Also, after the server sends a challenge,the client is supposed to
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
  private final DigestAlgorithm digestAlgorithm;

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
    private Optional<DigestAlgorithm> digestAlgorithm = Optional.absent();

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

    public Builder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
      this.digestAlgorithm = Optional.of(digestAlgorithm);
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
          secret,
          digestAlgorithm.or(new VerifiableDigestAlgorithm(secret)));
     }
  }

  /**
   * Constructor. The use of a builder is preferred as it provides sensible defaults for most
   * parameters.
   * @param tokenLifetimeInS The time span over which a token is valid, in seconds.
   * @param serverName The authentication server's name, preferably its fully qualified domain name.
   * @param keyProvider
   * @param timeSupplier An implementation of the {@code TimeSupplier} interface, used internally
   *    as a time reference. Use {@code RealTimeSupplier}
   * @param random A source of randomness.
   * @param secret A byte array that represents the server secret. Used as part of Hash-based
   *    message authentication codes to verify the source of requests.
   * @param digestAlgorithm An implementation of the {@code DigestAlgorithm} interface, used to
   *    compute Hash-based message authentication codes. Make sure that the client and the server
   *    use the same digestAlgorithm.
   */
  public CrtAuthServer(UnsignedInteger tokenLifetimeInS, String serverName, KeyProvider keyProvider,
      TimeSupplier timeSupplier, Random random, byte[] secret, DigestAlgorithm digestAlgorithm) {
    this.tokenLifetimeInS = tokenLifetimeInS;
    this.serverName = serverName;
    this.keyProvider = keyProvider;
    this.timeSupplier = timeSupplier;
    this.random = random;
    checkArgument(secret != null && secret.length > 0);
    this.secret = Arrays.copyOf(secret, secret.length);
    this.digestAlgorithm = digestAlgorithm;
  }

  /**
   * Create a challenge to authenticate a given user.
   * @param userName The username of the user to be authenticated, in the format required by
   *    KeyProviders
   * @return A challenge wrapped in a verifiable message, to be processed by the client.
   * @throws KeyNotFoundException when the public key for the requesting user is not available.
   */
  public VerifiableMessage<Challenge> createChallenge(String userName) throws KeyNotFoundException {
    RSAPublicKey key = keyProvider.getKey(userName);
    byte[] uniqueData = new byte[Challenge.UNIQUE_DATA_LENGTH];
    UnsignedInteger timeNow = timeSupplier.getTime();
    random.nextBytes(uniqueData);
    Challenge challenge = Challenge.newBuilder()
        .setFingerprint(PublicKeys.generateFingerprint(key))
        .setUniqueData(uniqueData)
        .setValidFromTimestamp(timeNow.minus(CLOCK_FUDGE))
        .setValidToTimestamp(timeNow.plus(RESPONSE_TIMEOUT))
        .setServerName(serverName)
        .setUserName(userName)
        .build();
    byte[] digest;
    try {
      digest = digestAlgorithm.getDigest(challenge.serialize());
    } catch (SerializationException e) {
      // This should never happen. If a SerializationException is thrown,
      // we rethrow it as a RuntimeException, since this is an unrecoverable condition anyway.
      throw new RuntimeException(e);
    }
    VerifiableMessage<Challenge> verifiableChallenge =
        new VerifiableMessage.Builder<Challenge>(Challenge.class)
            .setDigest(digest)
            .setPayload(challenge)
            .build();
    return verifiableChallenge;
  }

  /**
   * Given the response to a previous challenge, produce a token is the response is valid or
   * throw if it's not.
   * @param response The client's response to the intial challenge.
   * @return A token wrapped in a verifiable message.
   * @throws InvalidInputException
   */
  public VerifiableMessage<Token> createToken(Response response) throws InvalidInputException {
    if(!response.getVerifiableChallenge().verify(digestAlgorithm)) {
      throw new InvalidInputException(
          "Challenge hmac verification failed, not matching our secret");
    }
    Challenge challenge = response.getVerifiableChallenge().getPayload();
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
      signature.update(response.getVerifiableChallenge().getPayload().serialize());
      signatureVerified = signature.verify(response.getSignature());
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
    Token token = new Token.Builder()
        .setUserName(challenge.getUserName())
        .setValidFrom(validFrom)
        .setValidTo(validTo)
        .build();
    byte[] serializedToken = null;
    try {
      serializedToken = token.serialize();
    } catch (SerializationException e) {
      throw new RuntimeException(e);
    }
    VerifiableMessage<Token> verifiableToken = new VerifiableMessage.Builder<Token>(Token.class)
        .setDigest(digestAlgorithm.getDigest(serializedToken))
        .setPayload(token)
        .build();
    return verifiableToken;
  }

  /**
   * Verify that a given token is valid, i.e. that it has been produced by the current
   * authenticator and that it's not outside of its validity period.
   * @param verifiableToken A token wrapped in a {@code VerifiableMessage}.
   * @throws InvalidInputException If the token appears to have been tampered with.
   * @throws TokenExpiredException If the token is outside of its validity period.
   */
  public void validateToken(VerifiableMessage<Token> verifiableToken)
      throws InvalidInputException, TokenExpiredException {
    if (!verifiableToken.verify(digestAlgorithm)) {
      throw new InvalidInputException("Token hmac verification failed");
    }
    Token token = verifiableToken.getPayload();
    if (token.isExpired(timeSupplier)) {
      throw new TokenExpiredException("The token is out if its validity period.");
    }
  }
}
