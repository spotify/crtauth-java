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
import com.spotify.crtauth.exceptions.DeserializationException;
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
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
   * Create a challenge to authenticate a given user. The userName needs to be provided at this
   * stage to encode a fingerprint of the public key stored in the server encoded in the challenge.
   * This is required because a client can hold more than one private key and would need this
   * information to pick the right key to sign the response.
   *
   * @param userName The username of the user to be authenticated, in the format required by
   *    KeyProvider instances
   * @return A challenge wrapped in a verifiable message, to be processed by the client.
   * @throws KeyNotFoundException when the public key for the requesting user is not available.
   */
  public String createChallenge(String userName) throws KeyNotFoundException {
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
        new VerifiableMessage.Builder<>(Challenge.class)
            .setDigest(digest)
            .setPayload(challenge)
            .build();
    try {
      return encode(verifiableChallenge.serialize());
    } catch (SerializationException e) {
      throw new Error(e);
    }
  }

  /**
   * Given the response to a previous challenge, produce a token used by the client to authenticate.
   *
   * @param response The client's response to the initial challenge.
   * @return A token used to authenticate subsequent requests.
   * @throws InvalidInputException
   */
  public String createToken(String response) throws InvalidInputException {
    Response decodedResponse;
    try {
      decodedResponse = new Response().deserialize(decode(response));
    } catch (DeserializationException e) {
      throw new InvalidInputException(e);
    }
    if(!decodedResponse.getVerifiableChallenge().verify(digestAlgorithm)) {
      throw new InvalidInputException(
          "Challenge hmac verification failed, not matching our secret");
    }
    Challenge challenge = decodedResponse.getVerifiableChallenge().getPayload();
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
      signature.update(decodedResponse.getVerifiableChallenge().getPayload().serialize());
      signatureVerified = signature.verify(decodedResponse.getSignature());
    } catch (NoSuchAlgorithmException |
        InvalidKeyException |
        SignatureException |
        SerializationException e) {
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
    VerifiableMessage<Token> verifiableToken = new VerifiableMessage.Builder<>(Token.class)
        .setDigest(digestAlgorithm.getDigest(serializedToken))
        .setPayload(token)
        .build();
    try {
      return encode(verifiableToken.serialize());
    } catch (SerializationException e) {
      throw new Error(e);
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
    VerifiableMessage<Token> tokenDecoder = VerifiableMessage.getDefaultInstance(Token.class);
    byte[] data = decode(token);
    VerifiableMessage<Token> verifiableToken;
    try {
      verifiableToken = tokenDecoder.deserialize(data);
    } catch (DeserializationException e) {
      throw new InvalidInputException(String.format("failed deserialize token '%s'", token));
    }

    if (!verifiableToken.verify(digestAlgorithm)) {
      throw new InvalidInputException("Token hmac verification failed");
    }
    Token payload = verifiableToken.getPayload();
    if (payload.isExpired(timeSupplier)) {
      throw new TokenExpiredException("The token is out if its validity period.");
    }
    return payload.getUserName();
  }
}
