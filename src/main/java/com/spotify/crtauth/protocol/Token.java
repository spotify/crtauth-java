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

import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

import java.io.IOException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class Token implements XdrSerializable {
  private static final String MAGIC = "t";
  private int validFrom;
  private int validTo;
  private String userName;

  public static class Builder {
    Token token = new Token();

    public Builder setValidFrom(int validFrom) {
      token.validFrom = validFrom;
      return this;
    }

    public Builder setValidFrom(UnsignedInteger validFrom) {
      token.validFrom = validFrom.intValue();
      return this;
    }

    public Builder setValidTo(int validTo) {
      token.validTo = validTo;
      return this;
    }

    public Builder setValidTo(UnsignedInteger validTo) {
      token.validTo = validTo.intValue();
      return this;
    }

    public Builder setUserName(String userName) {
      token.userName = userName;
      return this;
    }

    public Token build() {
      checkNotNull(token.userName);
      Token built = token;
      token = new Token();
      return built;
    }
  }

  private Token() {}

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


  public static Token getDefaultInstance() {
    return new Token();
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
    } catch (IOException e) {
      throw new SerializationException();
    }
  }

  @Override
  public Token deserialize(byte[] bytes) throws DeserializationException {
    XdrDecoder decoder = Xdr.newDecoder(bytes);
    Token token = new Token();
    try {
      String magic = decoder.readFixedLengthString(1);
      checkArgument(magic.equals(MAGIC));
      token.validFrom = decoder.readInt();
      token.validTo = decoder.readInt();
      token.userName = decoder.readString();
      return token;
    } catch (IOException e) {
      throw new DeserializationException();
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
