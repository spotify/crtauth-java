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

import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class Response implements XdrSerializable {
  private static final String MAGIC = "r";

  private final byte[] signature;
  private final VerifiableMessage<Challenge> verifiableChallenge;

  public static class Builder {
    private byte[] signature;
    private VerifiableMessage<Challenge> verifiableChallenge;

    public Builder setSignature(byte[] signature) {
      this.signature = Arrays.copyOf(signature, signature.length);
      return this;
    }

    public Builder setVerifiableChallenge(
        VerifiableMessage<Challenge> verifiableChallenge) {
      this.verifiableChallenge = verifiableChallenge;
      return this;
    }

    public Response build() {
      return new Response(signature, verifiableChallenge);
    }
  }

  private static final MessageDeserializer<Response> DESERIALIZER = new MessageDeserializer<Response>() {
    @Override
    public Response deserialize(byte[] data)
        throws DeserializationException {
      final XdrDecoder decoder = Xdr.newDecoder(data);

      final String magic;

      try {
        magic = decoder.readFixedLengthString(1);
      } catch (XdrException e) {
        throw new DeserializationException(e);
      }

      if (!magic.equals(MAGIC)) {
        throw new DeserializationException("invalid magic byte");
      }

      final byte[] signature;
      final VerifiableMessage<Challenge> verifiableChallenge;

      try {
        signature = decoder.readVariableLengthOpaque();
        verifiableChallenge = VerifiableMessage.deserialize(decoder
            .readVariableLengthOpaque(), Challenge.deserializer());
      } catch (XdrException e) {
        throw new DeserializationException(e);
      }

      return new Response(signature, verifiableChallenge);
    }
  };

  public static MessageDeserializer<Response> deserializer() {
    return DESERIALIZER;
  }

  public Response(byte[] signature,
      VerifiableMessage<Challenge> verifiableChallenge) {
    if (signature == null)
      throw new IllegalArgumentException("'signature' must be set");

    if (verifiableChallenge == null)
      throw new IllegalArgumentException("'verifiableChallenge' must be set");

    this.signature = signature;
    this.verifiableChallenge = verifiableChallenge;
  }

  public VerifiableMessage<Challenge> getVerifiableChallenge() {
    return verifiableChallenge;
  }

  public byte[] getSignature() {
    return Arrays.copyOf(signature, signature.length);
  }

  @Override
  public byte[] serialize() throws SerializationException {
    final XdrEncoder encoder = Xdr.newEncoder();

    try {
      encoder.writeFixedLengthString(1, MAGIC);
      encoder.writeVariableLengthOpaque(signature);
      encoder.writeVariableLengthOpaque(verifiableChallenge.serialize());
      return encoder.encode();
    } catch (XdrException e) {
      throw new SerializationException(e);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;

    Response response = (Response) o;

    if (!Arrays.equals(signature, response.signature))
      return false;
    if (!verifiableChallenge.equals(response.verifiableChallenge))
      return false;

    return true;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(signature);
    result = 31 * result + verifiableChallenge.hashCode();
    return result;
  }
}
