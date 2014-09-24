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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

import com.spotify.crtauth.digest.DigestAlgorithm;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class VerifiableMessage<T extends XdrSerializable> implements XdrSerializable {
  private static final String MAGIC = "v";
  private byte[] digest;
  private T payload;
  private Class<T> payloadClass;

  public static class Builder<T extends XdrSerializable> {
    VerifiableMessage<T> verifiableMessage;

    public Builder(Class<T> clazz) {
      verifiableMessage = new VerifiableMessage<T>(clazz);
    }

    public Builder<T> setDigest(byte[] digest) {
      verifiableMessage.digest = digest;
      return this;
    }

    public Builder<T> setPayload(T payload) {
      verifiableMessage.payload = payload;
      return this;
    }

    public VerifiableMessage<T> build() {
      checkNotNull(verifiableMessage.digest);
      checkNotNull(verifiableMessage.payload);
      checkNotNull(verifiableMessage.payloadClass);
      VerifiableMessage<T> built = verifiableMessage;
      verifiableMessage = null;
      return built;
    }
  }

  private VerifiableMessage(Class<T> clazz) {
    payloadClass = clazz;
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


  public static <T extends XdrSerializable> VerifiableMessage<T> getDefaultInstance(
      Class<T> clazz) {
    return new VerifiableMessage<T>(clazz);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    @SuppressWarnings("unchecked")
    VerifiableMessage<T> that = (VerifiableMessage<T>) o;

    if (!Arrays.equals(digest, that.digest)) return false;
    if (!payload.equals(that.payload)) return false;
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

  @Override
  public VerifiableMessage<T> deserialize(byte[] bytes) throws DeserializationException {
    try {
      VerifiableMessage<T> verifiableMessage = new VerifiableMessage<T>(this.payloadClass);
      XdrDecoder decoder = Xdr.newDecoder(bytes);
      String magic = decoder.readFixedLengthString(1);
      checkArgument(magic.equals(MAGIC));
      verifiableMessage.digest = decoder.readFixedLengthOpaque(
          DigestAlgorithm.DIGEST_LENGTH);
      byte[] payloadBytes = decoder.readVariableLengthOpaque();
      T payloadDeserializer = buildNestedInstance();
      verifiableMessage.payload = (T) payloadDeserializer.deserialize(payloadBytes);
      return verifiableMessage;
    } catch (XdrException e) {
      throw new DeserializationException(e);
    }
  }

  private T buildNestedInstance() throws DeserializationException {
    try {
      return payloadClass.getConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new DeserializationException("failed to build nested instance", e);
    }
  }
}
