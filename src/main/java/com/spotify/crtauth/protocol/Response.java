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

import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class Response implements XdrSerializable {
  private static final String MAGIC = "r";
  private byte[] signature;
  private VerifiableMessage<Challenge> verifiableChallenge;

  public static class Builder {
    Response response = new Response();

    public Builder setSignature(byte[] signature) {
      response.signature = Arrays.copyOf(signature, signature.length);
      return this;
    }

    public Builder setVerifiableChallenge(VerifiableMessage<Challenge> verifiableChallenge) {
      response.verifiableChallenge = verifiableChallenge;
      return this;
    }

    public Response build() {
      checkNotNull(response.signature);
      checkNotNull(response.verifiableChallenge);
      Response built = response;
      response = new Response();
      return built;
    }
  }

  public VerifiableMessage<Challenge> getVerifiableChallenge() {
    return verifiableChallenge;
  }

  public byte[] getSignature() {
    return Arrays.copyOf(signature, signature.length);
  }

  @Override
  public byte[] serialize() throws SerializationException {
    XdrEncoder encoder = Xdr.newEncoder();
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
  public Response deserialize(byte[] bytes) throws DeserializationException {
    XdrDecoder decoder = Xdr.newDecoder(bytes);
    VerifiableMessage<Challenge> verifiableMessageDecoder =
        VerifiableMessage.getDefaultInstance(Challenge.class);
    Response response = new Response();
    try {
      String magic = decoder.readFixedLengthString(1);
      checkArgument(magic.equals(MAGIC));
      response.signature = decoder.readVariableLengthOpaque();
      byte[] verifiableMessageBytes = decoder.readVariableLengthOpaque();
      response.verifiableChallenge = verifiableMessageDecoder.deserialize(verifiableMessageBytes);
      return response;
    } catch (XdrException e) {
      throw new DeserializationException(e);

    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Response response = (Response) o;

    if (!Arrays.equals(signature, response.signature)) return false;
    if (!verifiableChallenge.equals(response.verifiableChallenge)) return false;

    return true;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(signature);
    result = 31 * result + verifiableChallenge.hashCode();
    return result;
  }
}
