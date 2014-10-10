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

package com.spotify.crtauth.protocol;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

import com.spotify.crtauth.digest.DigestAlgorithm;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class VerifiableMessage<T extends XdrSerializable> implements
    XdrSerializable {
  private static final String MAGIC = "v";

  private final byte[] digest;
  private final T payload;

  public static class Builder<T extends XdrSerializable> {
    private byte[] digest;
    private T payload;

    public Builder<T> setDigest(byte[] digest) {
      this.digest = digest;
      return this;
    }

    public Builder<T> setPayload(T payload) {
      this.payload = payload;
      return this;
    }

    public VerifiableMessage<T> build() {
      return new VerifiableMessage<T>(digest, payload);
    }
  }

  public VerifiableMessage(byte[] digest, T payload) {
    if (digest == null)
      throw new IllegalArgumentException("'digest' must be set");

    if (payload == null)
      throw new IllegalArgumentException("'payload' must be set");

    this.digest = digest;
    this.payload = payload;
  }

  public T getPayload() {
    return payload;
  }

  public boolean verify(DigestAlgorithm digestAlgorithm) {
    try {
      checkNotNull(digestAlgorithm);
      byte[] computedDigest = digestAlgorithm.getDigest(payload.serialize());
      return Arrays.equals(digest, computedDigest);
    } catch (SerializationException e) {
      return false;
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;

    @SuppressWarnings("unchecked")
    VerifiableMessage<T> that = (VerifiableMessage<T>) o;

    if (!Arrays.equals(digest, that.digest))
      return false;
    if (!payload.equals(that.payload))
      return false;
    return true;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(digest);
    result = 31 * result + payload.hashCode();
    return result;
  }

  @Override
  public byte[] serialize() throws SerializationException {
    try {
      checkNotNull(payload);
      XdrEncoder encoder = Xdr.newEncoder();
      encoder.writeFixedLengthString(1, MAGIC);
      encoder.writeFixedLengthOpaque(DigestAlgorithm.DIGEST_LENGTH, digest);
      encoder.writeVariableLengthOpaque(payload.serialize());
      return encoder.encode();
    } catch (XdrException e) {
      throw new SerializationException(e);
    }
  }

  public static <T extends XdrSerializable> VerifiableMessage<T> deserialize(byte[] data, MessageDeserializer<T> deserializer) throws DeserializationException {
    final XdrDecoder decoder = Xdr.newDecoder(data);

    final String magic;

    try {
      magic = decoder.readFixedLengthString(1);
    } catch(XdrException e) {
      throw new DeserializationException(e);
    }

    if (!magic.equals(MAGIC)) {
      throw new DeserializationException("invalid magic byte");
    }

    final byte[] digest;
    final byte[] payloadBytes;

    try {
      digest = decoder.readFixedLengthOpaque(DigestAlgorithm.DIGEST_LENGTH);
      payloadBytes = decoder.readVariableLengthOpaque();
    } catch(XdrException e) {
      throw new DeserializationException(e);
    }

    final T message = deserializer.deserialize(payloadBytes);

    return new VerifiableMessage<T>(digest, message);
  }
}
