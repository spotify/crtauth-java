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

package com.spotify.crtauth.protocol;

import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.exceptions.ProtocolVersionException;
import com.spotify.crtauth.utils.ASCIICodec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
   * @param challenge   the challenge to serialize
   * @param hmacSecret the secret used to generate the HMAC field
   * @return an array of bytes representing the provided Challenge
   */
  public static byte[] serialize(Challenge challenge, byte[] hmacSecret) {
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
    byte[] mac = getAuthenticationCode(hmacSecret, bytes);
    packer.pack(mac);
    return packer.getBytes();
  }

  public static Challenge deserializeChallenge(byte[] data)
      throws IllegalArgumentException, ProtocolVersionException {
    return doDeserializeChallenge(new MiniMessagePack.Unpacker(data));
  }

  public static Challenge deserializeChallengeAuthenticated(byte[] data, byte[] hmacSecret)
      throws IllegalArgumentException, ProtocolVersionException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    Challenge c = doDeserializeChallenge(unpacker);
    byte[] digest = getAuthenticationCode(hmacSecret, data, unpacker.getBytesRead());
    try {
      if (!constantTimeEquals(digest, unpacker.unpackBin())) {
        throw new IllegalArgumentException("HMAC validation failed");
      }
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
    return c;
  }

  /**
   * Serialize a Response into binary representation
   *
   * @param response the Response to serialize.
   * @return an array of bytes representing the provided Response
   */
  public static byte[] serialize(Response response) {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(VERSION);
    packer.pack(RESPONSE_MAGIC);
    packer.pack(response.getPayload());
    packer.pack(response.getSignature());
    return packer.getBytes();
  }

  public static Response deserializeResponse(byte[] data)
      throws IllegalArgumentException, ProtocolVersionException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    try {
      parseVersionMagic(RESPONSE_MAGIC, unpacker);
      return new Response(
          unpacker.unpackBin(), // challenge
          unpacker.unpackBin()  // signature
      );
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  public static Token deserializeTokenAuthenticated(byte[] data, byte[] hmacSecret)
      throws IllegalArgumentException, ProtocolVersionException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    try {
      Token token = doDeserializeToken(unpacker);
      byte[] digest = getAuthenticationCode(hmacSecret, data, unpacker.getBytesRead());
      if (!constantTimeEquals(digest, unpacker.unpackBin())) {
        throw new IllegalArgumentException("HMAC validation failed");
      }
      return token;
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e.getMessage());
    }

  }

  public static byte[] serialize(Token token, byte[] hmacSecret) {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack((byte) 0x01);
    packer.pack(TOKEN_MAGIC);
    packer.pack(token.getValidFrom());
    packer.pack(token.getValidTo());
    packer.pack(token.getUserName());
    packer.pack(getAuthenticationCode(hmacSecret, packer.getBytes()));
    return packer.getBytes();
  }


  private static Challenge doDeserializeChallenge(MiniMessagePack.Unpacker unpacker)
      throws IllegalArgumentException, ProtocolVersionException {
    try {
      parseVersionMagic(CHALLENGE_MAGIC, unpacker);
      return new Challenge(
          unpacker.unpackBin(),                  // unique data
          unpacker.unpackInt(),                  // validFromTimestamp
          unpacker.unpackInt(),                  // validToTimestamp
          new Fingerprint(unpacker.unpackBin()), // fingerprint
          unpacker.unpackString(),               // serverName
          unpacker.unpackString()                // username
      );
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private static Token doDeserializeToken(MiniMessagePack.Unpacker unpacker)
      throws IllegalArgumentException, ProtocolVersionException {
    try {
      parseVersionMagic(TOKEN_MAGIC, unpacker);
      return new Token(
          unpacker.unpackInt(),   // validFrom
          unpacker.unpackInt(),   // validTo
          unpacker.unpackString() // userName
      );
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Calculate and return a keyed hash message authentication code, HMAC, as specified in RFC2104
   * using SHA256 as hash function.
   *
   * @param secret the secret used to authenticate
   * @param data   the data to authenticate
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
   * Create a request string from a username. Request is too trivial for it to make it into a class
   * of it's own a this stage.
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
   * Deserialize an ASCII encoded request messages and return the username string it encodes. Also
   * verifies that the type magic value matches and that the version equals 1.
   *
   * @param request the ASCII encoded request String
   * @return the username encoded in the String
   */
  public static String deserializeRequest(String request)
      throws IllegalArgumentException, ProtocolVersionException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(ASCIICodec.decode(request));
    try {
      parseVersionMagic(REQUEST_MAGIC, unpacker);
      return unpacker.unpackString();
    } catch (DeserializationException e) {
      throw new IllegalArgumentException(e.getMessage());
    }

  }

  private static void parseVersionMagic(byte magic, MiniMessagePack.Unpacker unpacker)
      throws ProtocolVersionException, DeserializationException {

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

 /**
   * Checks if byte arrays a and be are equal in an algorithm that runs in
   * constant time provided that their lengths are equal.
   *
   * @param a the first byte array
   * @param b the second byte array
   * @return true if a and be are equal, else false
   */
  private static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }

    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}
