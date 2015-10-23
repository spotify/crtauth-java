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

import com.google.common.hash.Hashing;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkPositionIndex;

/**
 * Instances of this class contains a compact representation of the information needed to identify a
 * specific public key used to to sign a payload using the Signer interface. This piece of
 * information then gets sent from the server to the client to ensure that the right key gets picked
 * if there are many signing keys available.
 *
 * The bytes consists of the 6 first bytes of a SHA-1 hash of the traditional binary representation
 * of an RSA key used by ssh-keygen, a simple length value encoding with a 4 byte big endian  length
 * followed by the value as a binary number first the public exponent followed by the modulus.
 */
public class Fingerprint {

  private static final int FINGERPRINT_LENGTH = 6;
  // The size of a newly generated public part of a 4096 bit key
  private static final int TYPICAL_KEY_SIZE = 535;

  private final byte[] bytes;

  // TODO: Move CrtAuthCodec into the same package, and make this constructor package local
  public Fingerprint(byte[] fingerprint) {
    this.bytes = fingerprint;
  }

  /**
   * Calculate a bytes from the provided public key.
   *
   * @param publicKey the RSAPublicKey instance to make this fingerprint match
   */
  public Fingerprint(RSAPublicKey publicKey) {
    byte[] digestBytes = Hashing.sha1().hashBytes(getDerEncoding(publicKey)).asBytes();
    checkPositionIndex(FINGERPRINT_LENGTH, digestBytes.length);
    this.bytes = Arrays.copyOf(digestBytes, FINGERPRINT_LENGTH);
  }

  public byte[] getBytes() {
    return bytes;
  }

  /**
   * Returns true if this Fingerprint matches the public key other
   *
   * @param other the other RSAPublicKey to match
   * @return true if this Fingerprint matches other, else false
   */
  public boolean matches(RSAPublicKey other) {
    return this.equals(new Fingerprint(other));
  }

  private static byte[] getDerEncoding(RSAPublicKey key) {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream(TYPICAL_KEY_SIZE);
    DataOutputStream dataOutput = new DataOutputStream(buffer);
    writeVariableLengthOpaque("ssh-rsa".getBytes(), dataOutput);
    writeVariableLengthOpaque(key.getPublicExponent().toByteArray(), dataOutput);
    writeVariableLengthOpaque(key.getModulus().toByteArray(), dataOutput);
    return buffer.toByteArray();
  }

  private static void writeVariableLengthOpaque(byte[] opaque, DataOutput byteBuffer) {
    try {
      byteBuffer.writeInt(opaque.length);
      byteBuffer.write(opaque);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Fingerprint that = (Fingerprint) o;

    return Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
