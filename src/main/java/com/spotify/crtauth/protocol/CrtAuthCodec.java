/*
 * Copyright (c) 2014 Spotify AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/license/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.spotify.crtauth.protocol;

import com.spotify.crtauth.ASCIICodec;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.ProtocolVersionException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.Fingerprint;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * This class is used to encode and decode the different messages of the crtauth protocol between
 * binary and object representation.
 */
public class CrtAuthCodec {

  private static final byte VERSION = 1;
  private static final byte CHALLENGE_MAGIC = 'c';
  private static final byte RESPONSE_MAGIC = 'r';
  private static final byte TOKEN_MAGIC = 't';
  private static final byte REQUEST_MAGIC = 'q';


  private static final String MAC_ALGORITHM = "HmacSHA256";

  /**
   * Serialize a challenge into it's binary representation
   *
   * @param challenge the challenge to serialize
   * @param hmac_secret the secret used to generate the HMAC field
   * @return an array of bytes representing the provided Challenge
   * @throws SerializationException if serialization failed
   */
  public static byte[] serialize(Challenge challenge, byte[] hmac_secret)
      throws SerializationException {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(VERSION);
    packer.pack(CHALLENGE_MAGIC);
    packer.pack(challenge.getUniqueData());
    packer.pack(challenge.getValidFromTimestamp());
    packer.pack(challenge.getValidToTimestamp());
    packer.pack(challenge.getFingerprint().getBytes());
    packer.pack(challenge.getServerName());
    packer.pack(challenge.getUserName());
    byte[] bytes = packer.getBytes();
    byte[] mac = getAuthenticationCode(hmac_secret, bytes);
    packer.pack(mac);
    return packer.getBytes();
  }

  public static Challenge deserializeChallenge(byte[] data) throws DeserializationException {
    return doDeserializeChallenge(new MiniMessagePack.Unpacker(data));
  }

  public static Challenge deserializeChallengeAuthenticated(byte[] data, byte[] hmac_secret)
      throws DeserializationException, InvalidInputException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    Challenge c = doDeserializeChallenge(unpacker);
    byte[] digest = getAuthenticationCode(hmac_secret, data, unpacker.getBytesRead());
    if (!Arrays.equals(digest, unpacker.unpackBin())) {
      throw new InvalidInputException("HMAC validation failed");
    }
    return c;
  }

  /**
   * Serialize a Response into binary representation
   *
   * @param response the Response to serialize.
   * @return an array of bytes representing the provided Response
   * @throws SerializationException
   */
  public static byte[] serialize(Response response) throws SerializationException {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(VERSION);
    packer.pack(RESPONSE_MAGIC);
    packer.pack(response.getPayload());
    packer.pack(response.getSignature());
    return packer.getBytes();
  }

  public static Response deserializeResponse(byte[] data)
      throws DeserializationException, InvalidInputException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    parseVersionMagic(RESPONSE_MAGIC, unpacker);
    return new Response(
        unpacker.unpackBin(), // challenge
        unpacker.unpackBin()  // signature
    );
  }

  public static Token deserializeToken(byte[] data) throws DeserializationException {
    return doDeserializeToken(new MiniMessagePack.Unpacker(data));
  }

  public static Token deserializeTokenAuthenticated(byte[] data, byte[] hmac_secret)
      throws DeserializationException, InvalidInputException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    Token c = doDeserializeToken(unpacker);
    byte[] digest = getAuthenticationCode(hmac_secret, data, unpacker.getBytesRead());
    if (!Arrays.equals(digest, unpacker.unpackBin())) {
      throw new InvalidInputException("HMAC validation failed");
    }
    return c;
  }

  public static byte[] serialize(Token token, byte[] hmac_secret) throws SerializationException {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack((byte) 0x01);
    packer.pack(TOKEN_MAGIC);
    packer.pack(token.getValidFrom());
    packer.pack(token.getValidTo());
    packer.pack(token.getUserName());
    packer.pack(getAuthenticationCode(hmac_secret, packer.getBytes()));
    return packer.getBytes();
  }


  private static Challenge doDeserializeChallenge(MiniMessagePack.Unpacker unpacker)
      throws DeserializationException {
    parseVersionMagic(CHALLENGE_MAGIC, unpacker);
    return new Challenge(
        unpacker.unpackBin(),                  // unique data
        unpacker.unpackInt(),                  // validFromTimestamp
        unpacker.unpackInt(),                  // validToTimestamp
        new Fingerprint(unpacker.unpackBin()), // fingerprint
        unpacker.unpackString(),               // serverName
        unpacker.unpackString()                // username
    );
  }

  private static Token doDeserializeToken(MiniMessagePack.Unpacker unpacker) throws DeserializationException {
    parseVersionMagic(TOKEN_MAGIC, unpacker);
    return new Token(
        unpacker.unpackInt(),   // validFrom
        unpacker.unpackInt(),   // validTo
        unpacker.unpackString() // userName
    );
  }

  /**
   * Calculate and return a keyed hash message authentication code, HMAC, as specified in RFC2104
   * using SHA256 as hash function.
   *
   * @param secret the secret used to authenticate
   * @param data the data to authenticate
   * @param length the number of bytes from data to use when calculating the HMAC
   * @return an HMAC code for the specified data and secret
   */

  private static byte[] getAuthenticationCode(byte[] secret, byte[] data, int length) {
    try {
      SecretKey secretKey = new SecretKeySpec(secret, MAC_ALGORITHM);
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(secretKey);
      mac.update(data, 0, length);
      return mac.doFinal();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] getAuthenticationCode(byte[] secret, byte[] data) {
    return getAuthenticationCode(secret, data, data.length);
  }

  /**
   * Create a request string from a username. Request is too trivial for it to make it into a
   * class of it's own a this stage.
   *
   * @param username the username to encode
   * @return an encoded request message
   */
  public static String serializeEncodedRequest(String username) {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(1);
    packer.pack('q');
    packer.pack(username);
    return ASCIICodec.encode(packer.getBytes());
  }

  /**
   *
   *
   * @param request
   * @return
   */
  public static String deserializeRequest(String request) throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(ASCIICodec.decode(request));
    parseVersionMagic(REQUEST_MAGIC, unpacker);
    return unpacker.unpackString();
  }

  private static void parseVersionMagic(byte magic, MiniMessagePack.Unpacker unpacker)
      throws DeserializationException {

    byte version = unpacker.unpackByte();
    if (version != (byte) 0x01) {
      // version 0 protocol begins with ascii 'v' or ascii 'r'
      if (version == 0x76 || version == 0x72) {
        throw new ProtocolVersionException(
            "Received message using version 0 of the protocol. Only version 1 is supported");
      }
      throw new ProtocolVersionException(
          "Received a message with too new version of the protocol. " +
              "Only version 1 is supported, received version %d" + version
      );
    }
    byte readMagic = unpacker.unpackByte();
    if (readMagic != magic) {
      throw new DeserializationException(String.format(
          "invalid magic byte, expected %d but got %d", readMagic, magic));
    }
  }


}
