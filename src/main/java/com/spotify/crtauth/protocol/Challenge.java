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
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

public class Challenge implements XdrSerializable {
  public static final int UNIQUE_DATA_LENGTH = 20;
  private static final int FINGERPRINT_LENGTH = 6;
  private static final String MAGIC = "c";
  private byte[] uniqueData;
  private int validFromTimestamp;
  private int validToTimestamp;
  private byte[] figerprint;
  private String serverName;
  private String userName;

  public static class Builder {
    private Challenge challenge = new Challenge();

    public Builder setUniqueData(byte[] uniqueData) {
      checkArgument(uniqueData.length == UNIQUE_DATA_LENGTH);
      challenge.uniqueData = Arrays.copyOf(uniqueData, uniqueData.length);
      return this;
    }

    public Builder setValidFromTimestamp(UnsignedInteger timestamp) {
      challenge.validFromTimestamp = timestamp.intValue();
      return this;
    }

    public Builder setValidFromTimestamp(int timestamp) {
      challenge.validFromTimestamp = timestamp;
      return this;
    }

    public Builder setValidToTimestamp(UnsignedInteger timestamp) {
      challenge.validToTimestamp = timestamp.intValue();
      return this;
    }

    public Builder setValidToTimestamp(int timestamp) {
      challenge.validToTimestamp = timestamp;
      return this;
    }

    public Builder setFingerprint(byte[] fingerprint) {
      challenge.figerprint = Arrays.copyOf(fingerprint, FINGERPRINT_LENGTH);
      return this;
    }

    public Builder setServerName(String serverName) {
      challenge.serverName = serverName;
      return this;
    }

    public Builder setUserName(String userName) {
      challenge.userName = userName;
      return this;
    }

    public Challenge build() {
      Challenge built = challenge;
      challenge = new Challenge();
      return built;
    }
  }

  public Challenge() {}

  public static Builder newBuilder() {
    return new Builder();
  }

  public byte[] getUniqueData() {
    return Arrays.copyOf(uniqueData, uniqueData.length);
  }

  public int getValidFromTimestamp() {
    return validFromTimestamp;
  }

  public int getValidToTimestamp() {
    return validToTimestamp;
  }

  public byte[] getFigerprint() {
    return Arrays.copyOf(figerprint, figerprint.length);
  }

  public String getServerName() {
    return serverName;
  }

  public String getUserName() {
    return userName;
  }

  public boolean isExpired(TimeSupplier timeSupplier) {
    return TimeIntervals.isExpired(validFromTimestamp, validToTimestamp, timeSupplier);
  }


  @Override
  public byte[] serialize() throws SerializationException {
    XdrEncoder encoder = Xdr.newEncoder();
    try {
      encoder.writeFixedLengthString(1, MAGIC);
      encoder.writeFixedLengthOpaque(UNIQUE_DATA_LENGTH, uniqueData);
      encoder.writeInt(validFromTimestamp);
      encoder.writeInt(validToTimestamp);
      encoder.writeVariableLengthOpaque(figerprint);
      encoder.writeString(serverName);
      encoder.writeString(userName);
      return encoder.encode();
    } catch (IOException e) {
      throw new SerializationException();
    }
  }

  @Override
  public Challenge deserialize(byte[] bytes) throws DeserializationException {
    XdrDecoder decoder = Xdr.newDecoder(bytes);
    Challenge challenge = new Challenge();
    try {
      String magic = decoder.readFixedLengthString(1);
      if (!magic.equals(MAGIC)) {
        throw new DeserializationException();
      }
      challenge.uniqueData = decoder.readFixedLengthOpaque(UNIQUE_DATA_LENGTH);
      challenge.validFromTimestamp = decoder.readInt();
      challenge.validToTimestamp = decoder.readInt();
      challenge.figerprint = decoder.readVariableLengthOpaque();
      challenge.serverName = decoder.readString();
      challenge.userName = decoder.readString();
    } catch(IOException e) {
      throw new DeserializationException();
    }
    return challenge;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Challenge challenge = (Challenge) o;

    if (validFromTimestamp != challenge.validFromTimestamp) return false;
    if (validToTimestamp != challenge.validToTimestamp) return false;
    if (!Arrays.equals(figerprint, challenge.figerprint)) return false;
    if (!serverName.equals(challenge.serverName)) return false;
    if (!Arrays.equals(uniqueData, challenge.uniqueData)) return false;
    if (!userName.equals(challenge.userName)) return false;

    return true;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(uniqueData);
    result = 31 * result + validFromTimestamp;
    result = 31 * result + validToTimestamp;
    result = 31 * result + Arrays.hashCode(figerprint);
    result = 31 * result + serverName.hashCode();
    result = 31 * result + userName.hashCode();
    return result;
  }

}
