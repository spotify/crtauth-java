/*
 * Copyright (c) 2015 Spotify AB.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.primitives.UnsignedInteger;

import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.crtauth.exceptions.ProtocolVersionException;
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
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.spotify.crtauth.utils.ASCIICodec.decode;
import static com.spotify.crtauth.utils.ASCIICodec.encode;

/**
 * Instances of this class implements the server part of an crtauth authentication interaction. A
 * consumer of this class would typically provide a means for remote clients to call the
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
 * for tokens. A clock can be off at most CLOCK_FUGDE seconds before the server starts emitting too
 * new/too old messages. Also, after the server sends a challenge, the client is supposed to produce
 * a reply within RESP_TIMEOUT seconds.
 */
public class CrtAuthServer {

  private static final UnsignedInteger CLOCK_FUDGE = UnsignedInteger.fromIntBits(2);
  private static final UnsignedInteger RESPONSE_TIMEOUT = UnsignedInteger.fromIntBits(20);
  // The maximum token lifetime in seconds.
  private static final int MAX_VALIDITY = 600;
  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
  private final UnsignedInteger tokenLifetimeSeconds;
  private final String serverName;
  private final List<KeyProvider> keyProviders;
  private final TimeSupplier timeSupplier;
  private final Random random;
  private final byte[] secret;

  private static final Logger log = LoggerFactory.getLogger(CrtAuthServer.class);

  public static class Builder {

    private static final UnsignedInteger DEFAULT_TOKEN_LIFETIME_SECONDS =
        UnsignedInteger.fromIntBits(60);
    private static final TimeSupplier DEFAULT_TIME_SUPPLIER = new RealTimeSupplier();
    private Optional<UnsignedInteger> tokenLifetimeSeconds = Optional.absent();
    private String serverName;
    private List<KeyProvider> keyProviders = Lists.newArrayList();
    private Optional<TimeSupplier> timeSupplier = Optional.absent();
    private Optional<Random> random = Optional.absent();
    private byte[] secret;

    public Builder setTokenLifetimeSeconds(int tokenLifetimeSeconds) {
      this.tokenLifetimeSeconds = Optional.of(UnsignedInteger.fromIntBits(tokenLifetimeSeconds));
      return this;
    }

    public Builder setServerName(String serverName) {
      this.serverName = serverName;
      return this;
    }

    public Builder addKeyProvider(KeyProvider keyProvider) {
      this.keyProviders.add(keyProvider);
      return this;
    }

    public Builder setKeyProvider(KeyProvider keyProvider) {
      this.keyProviders.clear();
      this.keyProviders.add(keyProvider);
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
      checkNotNull(keyProviders);
      checkNotNull(secret);

      if (keyProviders.isEmpty()) {
        throw new IllegalArgumentException("At least one key provider must be specified.");
      }

      final UnsignedInteger lifetime = tokenLifetimeSeconds.or(DEFAULT_TOKEN_LIFETIME_SECONDS);
      if (lifetime.intValue() > MAX_VALIDITY) {
        throw new IllegalArgumentException(String.format(
            "Overly long token lifetime. Max lifetime is %d.", MAX_VALIDITY));
      }

      return new CrtAuthServer(lifetime,
                               serverName,
                               keyProviders,
                               timeSupplier.or(DEFAULT_TIME_SUPPLIER),
                               random.or(new Random()),
                               secret
      );
    }
  }

  private CrtAuthServer(UnsignedInteger tokenLifetimeSeconds, String serverName,
                        List<KeyProvider> keyProviders, TimeSupplier timeSupplier, Random random,
                        byte[] secret) {
    this.tokenLifetimeSeconds = tokenLifetimeSeconds;
    this.serverName = serverName;
    this.keyProviders = ImmutableList.copyOf(keyProviders);
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
   * @return A challenge message.
   * @throws IllegalArgumentException if the request format is invalid
   */
  public String createChallenge(String request)
      throws IllegalArgumentException, ProtocolVersionException {

    String userName;
    userName = CrtAuthCodec.deserializeRequest(request);

    Fingerprint fingerprint;
    try {
      fingerprint = new Fingerprint(getKeyForUser(userName));
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

    return encode(CrtAuthCodec.serialize(challenge, secret));
  }

  /**
   * Get the public key for a user by iterating through all key providers. The first
   * matching key will be returned.
   *
   * @param userName the username to get the key for
   * @return the first RSAPublicKey found for the user
   * @throws KeyNotFoundException
   */
  private RSAPublicKey getKeyForUser(String userName) throws KeyNotFoundException {
    RSAPublicKey key = null;
    for (final KeyProvider keyProvider : keyProviders) {
      try {
        key = keyProvider.getKey(userName);
        break;
      } catch (KeyNotFoundException e) {
        // that's fine, try the next provider
      }
    }

    if (key == null) {
      throw new KeyNotFoundException();
    }

    return key;
  }

  /**
   * Generate a fake real looking fingerprint for a non-existent user.
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
   * Given the response to a previous challenge, produce a token used by the client to
   * authenticate.
   *
   * @param response The client's response to the initial challenge.
   * @return A token used to authenticate subsequent requests.
   * @throws IllegalArgumentException if there is an encoding error in the response message
   */
  public String createToken(String response)
      throws IllegalArgumentException, ProtocolVersionException {
    final Response decodedResponse;
    final Challenge challenge;
    decodedResponse = CrtAuthCodec.deserializeResponse(decode(response));
    challenge = CrtAuthCodec.deserializeChallengeAuthenticated(
        decodedResponse.getPayload(), secret);

    if (!challenge.getServerName().equals(serverName)) {
      throw new IllegalArgumentException("Got challenge with the wrong server_name encoded.");
    }
    PublicKey publicKey;
    try {
      publicKey = getKeyForUser(challenge.getUserName());
    } catch (KeyNotFoundException e) {
      // If the user requesting authentication doesn't have a public key,  we throw an
      // InvalidInputException. This normally shouldn't happen, since at this stage a challenge
      // should have already been sent, which in turn requires knowledge of the user's public key.
      throw new IllegalArgumentException(e);
    }
    boolean signatureVerified;
    try {
      Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      signature.initVerify(publicKey);
      signature.update(decodedResponse.getPayload());
      signatureVerified = signature.verify(decodedResponse.getSignature());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    if (challenge.isExpired(timeSupplier)) {
      throw new IllegalArgumentException("The challenge is out of its validity period");
    }
    if (!signatureVerified) {
      throw new IllegalArgumentException("Client did not provide proof that it controls the " +
                                         "secret key.");
    }
    UnsignedInteger validFrom = timeSupplier.getTime().minus(CLOCK_FUDGE);
    UnsignedInteger validTo = timeSupplier.getTime().plus(tokenLifetimeSeconds);
    Token token = new Token(validFrom.intValue(), validTo.intValue(), challenge.getUserName());
    return encode(CrtAuthCodec.serialize(token, secret));
  }

  /**
   * Verify that a given token is valid, i.e. that it has been produced by the current authenticator
   * and that it hasn't expired.
   *
   * @param token the token to validate.
   * @return the username that this token belongs to.
   * @throws IllegalArgumentException If the token appears to have been tampered with.
   * @throws TokenExpiredException    If the token has expired.
   */
  public String validateToken(String token)
      throws IllegalArgumentException, TokenExpiredException, ProtocolVersionException {
    final Token deserializedToken =
        CrtAuthCodec.deserializeTokenAuthenticated(decode(token), secret);
    if (deserializedToken.isExpired(timeSupplier)) {
      throw new TokenExpiredException();
    }
    if (deserializedToken.getValidTo() - deserializedToken.getValidFrom() > MAX_VALIDITY) {
      throw new TokenExpiredException("Overly long token lifetime.");
    }
    return deserializedToken.getUserName();
  }
}
