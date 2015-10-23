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

package com.spotify.crtauth.utils;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.UnsignedBytes;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A set of utilities to parse private and public RSA PEM keys as produced by ssh-keygen.
 */
public class TraditionalKeyParser {

  private static final Pattern PUBLIC_KEY_PATTERN = Pattern.compile("^ssh-rsa (.+) .*$");
  private static final Pattern PRIVATE_KEY_PATTERN =
      Pattern.compile("^-+BEGIN RSA PRIVATE KEY-+([^-]+)-+END RSA PRIVATE KEY-+$");
  private static final int INTEGER_SIZE = Integer.SIZE;
  private static final String PUBLIC_KEY_TYPE = "ssh-rsa";

  public static RSAPublicKeySpec parsePemPublicKey(String pemPublicKey) throws InvalidKeyException {
    Matcher matcher = PUBLIC_KEY_PATTERN.matcher(pemPublicKey);
    if (!matcher.matches()) {
      throw new InvalidKeyException();
    }
    String pemKey = matcher.group(1);
    BaseEncoding encoding = BaseEncoding.base64();
    byte[] derKey = encoding.decode(pemKey);
    ByteBuffer byteBuffer = ByteBuffer.wrap(derKey);
    byteBuffer.order(ByteOrder.BIG_ENDIAN);
    byte[] typeBytes = readVariableLengthOpaque(byteBuffer);
    byte[] expBytes = readVariableLengthOpaque(byteBuffer);
    byte[] modBytes = readVariableLengthOpaque(byteBuffer);
    if (typeBytes == null || expBytes == null || modBytes == null) {
      throw new InvalidKeyException();
    }
    String type = new String(typeBytes, Charsets.US_ASCII);
    if (!type.equals(PUBLIC_KEY_TYPE)) {
      throw new InvalidKeyException();
    }
    BigInteger exp = new BigInteger(expBytes);
    BigInteger mod = new BigInteger(modBytes);
    return new RSAPublicKeySpec(mod, exp);
  }

  public static RSAPrivateKeySpec parsePemPrivateKey(String pemPrivateKey)
      throws InvalidKeyException {
    pemPrivateKey = pemPrivateKey.replace("\n", "");
    Matcher matcher = PRIVATE_KEY_PATTERN.matcher(pemPrivateKey);
    if (!matcher.matches()) {
      throw new InvalidKeyException();
    }
    String pemKey = matcher.group(1);
    BaseEncoding encoding = BaseEncoding.base64();
    byte[] derKey = encoding.decode(pemKey);
    List<byte[]> fields;
    try {
      fields = parsePrivateKeyASN1(ByteBuffer.wrap(derKey));
    } catch (IllegalArgumentException e) {
      throw new InvalidKeyException(e);
    }
    BigInteger mod = new BigInteger(fields.get(1));
    BigInteger exp = new BigInteger(fields.get(3));
    return new RSAPrivateKeySpec(mod, exp);
  }

  /**
   * This is a simplistic ASN.1 parser that can only parse a collection of primitive types.
   *
   * @param byteBuffer the raw byte representation of a Pcks1 private key.
   * @return A list of bytes array that represent the content of the original ASN.1 collection.
   */
  private static List<byte[]> parsePrivateKeyASN1(ByteBuffer byteBuffer) {
    final List<byte[]> collection = new ArrayList<byte[]>();
    while (byteBuffer.hasRemaining()) {
      byte type = byteBuffer.get();
      int length = UnsignedBytes.toInt(byteBuffer.get());
      if ((length & 0x80) != 0) {
        int numberOfOctets = length ^ 0x80;
        length = 0;
        for (int i = 0; i < numberOfOctets; ++i) {
          int lengthChunk = UnsignedBytes.toInt(byteBuffer.get());
          length += lengthChunk << (numberOfOctets - i - 1) * 8;
        }
      }
      if (length < 0) {
        throw new IllegalArgumentException();
      }
      if (type == 0x30) {
        int position = byteBuffer.position();
        byte[] data = Arrays.copyOfRange(byteBuffer.array(), position, position + length);
        return parsePrivateKeyASN1(ByteBuffer.wrap(data));
      }
      if (type == 0x02) {
        byte[] segment = new byte[length];
        byteBuffer.get(segment);
        collection.add(segment);
      }
    }
    return collection;
  }

  private static byte[] readVariableLengthOpaque(ByteBuffer byteBuffer) {
    if (byteBuffer.position() + INTEGER_SIZE > byteBuffer.limit()) {
      return null;
    }
    int length = byteBuffer.getInt();
    if (byteBuffer.position() + length > byteBuffer.limit()) {
      return null;
    }
    byte[] bytes = new byte[length];
    byteBuffer.get(bytes);
    return bytes;
  }
}
