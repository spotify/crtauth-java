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

package com.spotify.crtauth.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkPositionIndex;

public class PublicKeys {
  private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-1";
  private static final int FINGERPRINT_LENGHT = 6;
  private static final int INTEGER_SIZE = Integer.SIZE;
  private static final String PUBLIC_KEY_TYPE = "ssh-rsa";
  private final static int MAX_BUFFER_SIZE = 512 * 1024;

  /**
   * Obtain a 6-byte long fingerprint for the given RSA public key.
   * @param key A RSA public key.
   * @return A 6-byte long fingerprint. The fingerprint is computed out of the traditional
   *    representation, as produced by default by ssh-keygen. The binary-encoded representation of
   *    public exponent and modulus is hashed using sha1 and the first 6 bytes of the hash are
   *    returned.
   */
  public static byte[] generateFingerprint(RSAPublicKey key) {
    MessageDigest digest = null;
    try {
      digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    // Produce a traditional representation of the key in DER format
    byte[] derKey = getDerEncoding(key);
    // Compute a sha1 hash
    digest.reset();
    digest.update(derKey);
    byte[] digestBytes = digest.digest();
    checkPositionIndex(FINGERPRINT_LENGHT, digestBytes.length);
    return Arrays.copyOf(digestBytes, FINGERPRINT_LENGHT);
  }

  private static byte[] getDerEncoding(RSAPublicKey key) {
    byte[] type = PUBLIC_KEY_TYPE.getBytes();
    byte[] exp = key.getPublicExponent().toByteArray();
    byte[] mod = key.getModulus().toByteArray();
    byte[] buffer = new byte[MAX_BUFFER_SIZE];
    ByteBuffer byteBuffer = ByteBuffer.wrap(buffer);
    byteBuffer.order(ByteOrder.BIG_ENDIAN);
    writeVariableLengthOpaque(type, byteBuffer);
    writeVariableLengthOpaque(exp, byteBuffer);
    writeVariableLengthOpaque(mod, byteBuffer);
    return Arrays.copyOf(byteBuffer.array(), byteBuffer.position());
  }

  private static void writeVariableLengthOpaque(byte[] opaque, ByteBuffer byteBuffer) {
    if (byteBuffer.position() + opaque.length + INTEGER_SIZE > byteBuffer.limit()) {
      throw new RuntimeException("Buffer overflow.");
    }
    int length = opaque.length;
    byteBuffer.putInt(length);
    byteBuffer.put(opaque);
  }
}
