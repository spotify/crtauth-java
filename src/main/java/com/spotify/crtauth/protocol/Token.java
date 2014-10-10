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

import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class Token implements XdrSerializable {
  private static final String MAGIC = "t";

  private final int validFrom;
  private final int validTo;
  private final String userName;

  public static class Builder {
    private int validFrom;
    private int validTo;
    private String userName;

    public Builder setValidFrom(int validFrom) {
      this.validFrom = validFrom;
      return this;
    }

    public Builder setValidFrom(UnsignedInteger validFrom) {
      this.validFrom = validFrom.intValue();
      return this;
    }

    public Builder setValidTo(int validTo) {
      this.validTo = validTo;
      return this;
    }

    public Builder setValidTo(UnsignedInteger validTo) {
      this.validTo = validTo.intValue();
      return this;
    }

    public Builder setUserName(String userName) {
      this.userName = userName;
      return this;
    }

    public Token build() {
      return new Token(validFrom, validTo, userName);
    }
  }

  private static MessageDeserializer<Token> DESERIALIZER = new MessageDeserializer<Token>() {
    @Override
    public Token deserialize(byte[] data) throws DeserializationException {
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

      final int validFrom;
      final int validTo;
      final String userName;

      try {
        validFrom = decoder.readInt();
        validTo = decoder.readInt();
        userName = decoder.readString();
      } catch (XdrException e) {
        throw new DeserializationException(e);
      }

      return new Token(validFrom, validTo, userName);
    }
  };

  public static MessageDeserializer<Token> deserializer() {
    return DESERIALIZER;
  }

  public static Token deserialize(byte[] data) throws DeserializationException {
    return deserializer().deserialize(data);
  }

  public Token(int validFrom, int validTo, String userName) {
    if (!(validFrom < validTo))
      throw new IllegalArgumentException(
          "validity timestamps are invalid, 'validFrom' "
              + "must be smaller than 'validTo'");

    if (userName == null || userName.isEmpty())
      throw new IllegalArgumentException("'userName' must be set and non-empty");

    this.validFrom = validFrom;
    this.validTo = validTo;
    this.userName = userName;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public boolean isExpired(TimeSupplier timeSupplier) {
    return TimeIntervals.isExpired(validFrom, validTo, timeSupplier);
  }

  public int getValidFrom() {
    return validFrom;
  }

  public int getValidTo() {
    return validTo;
  }

  public String getUserName() {
    return this.userName;
  }

  @Override
  public byte[] serialize() throws SerializationException {
    XdrEncoder encoder = Xdr.newEncoder();
    try {
      encoder.writeFixedLengthString(1, MAGIC);
      encoder.writeInt(validFrom);
      encoder.writeInt(validTo);
      encoder.writeString(userName);
      return encoder.encode();
    } catch (XdrException e) {
      throw new SerializationException(e);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Token token = (Token) o;

    if (validFrom != token.validFrom) return false;
    if (validTo != token.validTo) return false;
    if (!userName.equals(token.userName)) return false;

    return true;
  }

  @Override
  public int hashCode() {
    int result = validFrom;
    result = 31 * result + validTo;
    result = 31 * result + userName.hashCode();
    return result;
  }
}
