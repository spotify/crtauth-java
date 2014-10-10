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

import java.util.Arrays;

import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.XdrException;
import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;
import com.spotify.crtauth.xdr.Xdr;
import com.spotify.crtauth.xdr.XdrDecoder;
import com.spotify.crtauth.xdr.XdrEncoder;

public class Challenge implements XdrSerializable {
  public static final int UNIQUE_DATA_LENGTH = 20;
  private static final int FINGERPRINT_LENGTH = 6;
  private static final String MAGIC = "c";

  private final byte[] uniqueData;
  private final int validFromTimestamp;
  private final int validToTimestamp;
  private final byte[] fingerprint;
  private final String serverName;
  private final String userName;

  public static class Builder {
    private byte[] uniqueData;
    private int validFromTimestamp;
    private int validToTimestamp;
    private byte[] fingerprint;
    private String serverName;
    private String userName;

    public Builder setUniqueData(byte[] uniqueData) {
      checkArgument(uniqueData.length == UNIQUE_DATA_LENGTH);
      this.uniqueData = Arrays.copyOf(uniqueData, uniqueData.length);
      return this;
    }

    public Builder setValidFromTimestamp(UnsignedInteger timestamp) {
      this.validFromTimestamp = timestamp.intValue();
      return this;
    }

    public Builder setValidFromTimestamp(int timestamp) {
      this.validFromTimestamp = timestamp;
      return this;
    }

    public Builder setValidToTimestamp(UnsignedInteger timestamp) {
      this.validToTimestamp = timestamp.intValue();
      return this;
    }

    public Builder setValidToTimestamp(int timestamp) {
      this.validToTimestamp = timestamp;
      return this;
    }

    public Builder setFingerprint(byte[] fingerprint) {
      this.fingerprint = Arrays.copyOf(fingerprint, FINGERPRINT_LENGTH);
      return this;
    }

    public Builder setServerName(String serverName) {
      this.serverName = serverName;
      return this;
    }

    public Builder setUserName(String userName) {
      this.userName = userName;
      return this;
    }

    public Challenge build() {
      return new Challenge(uniqueData, validFromTimestamp, validToTimestamp,
          fingerprint, serverName, userName);
    }
  }

  private static final MessageDeserializer<Challenge> DESERIALIZER = new MessageDeserializer<Challenge>() {
    @Override
    public Challenge deserialize(byte[] data) throws DeserializationException {
      final XdrDecoder decoder = Xdr.newDecoder(data);
      final String magic;

      try {
        magic = decoder.readFixedLengthString(1);
      } catch (final XdrException e) {
        throw new DeserializationException(e);
      }

      if (!magic.equals(MAGIC)) {
        throw new DeserializationException("invalid magic byte");
      }

      final byte[] uniqueData;
      final int validFromTimestamp;
      final int validToTimestamp;
      final byte[] fingerprint;
      final String serverName;
      final String userName;

      try {
        uniqueData = decoder.readFixedLengthOpaque(UNIQUE_DATA_LENGTH);
        validFromTimestamp = decoder.readInt();
        validToTimestamp = decoder.readInt();
        fingerprint = decoder.readVariableLengthOpaque();
        serverName = decoder.readString();
        userName = decoder.readString();
      } catch (final XdrException e) {
        throw new DeserializationException(e);
      }

      return new Challenge(uniqueData, validFromTimestamp, validToTimestamp,
          fingerprint, serverName, userName);
    }
  };

  public static MessageDeserializer<Challenge> deserializer() {
    return DESERIALIZER;
  }

  public Challenge(byte[] uniqueData, int validFromTimestamp,
      int validToTimestamp, byte[] fingerprint, String serverName,
      String userName) {
    if (uniqueData == null)
      throw new IllegalArgumentException("'uniqueData' must be set");

    if (fingerprint == null)
      throw new IllegalArgumentException("'fingerprint' must be set");

    if (!(validFromTimestamp < validToTimestamp))
      throw new IllegalArgumentException(
          "validity timestamps are invalid, 'validFromTimestamp' "
              + "must be smaller than 'validToTimestamp'");

    if (serverName == null || serverName.isEmpty())
      throw new IllegalArgumentException("'serverName' must be set and non-empty");

    if (userName == null || userName.isEmpty())
      throw new IllegalArgumentException("'userName' must be set and non-empty");

    this.uniqueData = uniqueData;
    this.validFromTimestamp = validFromTimestamp;
    this.validToTimestamp = validToTimestamp;
    this.fingerprint = fingerprint;
    this.serverName = serverName;
    this.userName = userName;
  }

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

  public byte[] getFingerprint() {
    return Arrays.copyOf(fingerprint, fingerprint.length);
  }

  public String getServerName() {
    return serverName;
  }

  public String getUserName() {
    return userName;
  }

  public boolean isExpired(TimeSupplier timeSupplier) {
    return TimeIntervals.isExpired(validFromTimestamp, validToTimestamp,
        timeSupplier);
  }

  @Override
  public byte[] serialize() throws SerializationException {
    final XdrEncoder encoder = Xdr.newEncoder();

    try {
      encoder.writeFixedLengthString(1, MAGIC);
      encoder.writeFixedLengthOpaque(UNIQUE_DATA_LENGTH, uniqueData);
      encoder.writeInt(validFromTimestamp);
      encoder.writeInt(validToTimestamp);
      encoder.writeVariableLengthOpaque(fingerprint);
      encoder.writeString(serverName);
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

    Challenge challenge = (Challenge) o;

    if (!Arrays.equals(uniqueData, challenge.uniqueData))
      return false;
    if (validFromTimestamp != challenge.validFromTimestamp)
      return false;
    if (validToTimestamp != challenge.validToTimestamp)
      return false;
    if (!Arrays.equals(fingerprint, challenge.fingerprint))
      return false;
    if (!serverName.equals(challenge.serverName))
      return false;
    if (!userName.equals(challenge.userName))
      return false;

    return true;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(uniqueData);
    result = 31 * result + validFromTimestamp;
    result = 31 * result + validToTimestamp;
    result = 31 * result + Arrays.hashCode(fingerprint);
    result = 31 * result + serverName.hashCode();
    result = 31 * result + userName.hashCode();
    return result;
  }
}
