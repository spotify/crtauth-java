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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.hash.Hashing;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkPositionIndex;

public class PublicKeys {
  private static final int FINGERPRINT_LENGTH = 6;
  // The size of a newly generated public part of a 4096 bit key
  private static final int TYPICAL_KEY_SIZE = 535;

  /**
   * Obtain a 6-byte long fingerprint for the given RSA public key.
   * @param key A RSA public key.
   * @return A 6-byte long fingerprint. The fingerprint is computed out of the traditional
   *    representation, as produced by default by ssh-keygen. The binary-encoded representation of
   *    public exponent and modulus is hashed using sha1 and the first 6 bytes of the hash are
   *    returned.
   */
  public static byte[] generateFingerprint(RSAPublicKey key) {
    byte[] digestBytes = Hashing.sha1().hashBytes(getDerEncoding(key)).asBytes();
    checkPositionIndex(FINGERPRINT_LENGTH, digestBytes.length);
    return Arrays.copyOf(digestBytes, FINGERPRINT_LENGTH);
  }

  private static byte[] getDerEncoding(RSAPublicKey key) {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream(TYPICAL_KEY_SIZE);
    DataOutputStream dataOutput = new DataOutputStream(buffer);
    writeVariableLengthOpaque("ssh-rsa".getBytes(), dataOutput);
    writeVariableLengthOpaque(key.getPublicExponent().toByteArray(), dataOutput);
    writeVariableLengthOpaque(key.getModulus().toByteArray(), dataOutput);
    return buffer.toByteArray();
  }

  @VisibleForTesting
  static void writeVariableLengthOpaque(byte[] opaque, DataOutput byteBuffer) {
    try {
      byteBuffer.writeInt(opaque.length);
      byteBuffer.write(opaque);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
