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

package com.spotify.crtauth.protocol;

import com.google.common.primitives.UnsignedInteger;

import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;

import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

public class Challenge {

  public static final int UNIQUE_DATA_LENGTH = 20;

  private final byte[] uniqueData;
  private final int validFromTimestamp;
  private final int validToTimestamp;
  private final Fingerprint fingerprint;
  private final String serverName;
  private final String userName;

  public static class Builder {

    private byte[] uniqueData;
    private int validFromTimestamp;
    private int validToTimestamp;
    private Fingerprint fingerprint;
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

    public Builder setFingerprint(Fingerprint fingerprint) {
      this.fingerprint = fingerprint;
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

  public Challenge(byte[] uniqueData, int validFromTimestamp,
                   int validToTimestamp, Fingerprint fingerprint, String serverName,
                   String userName) {
    if (uniqueData == null) {
      throw new IllegalArgumentException("'uniqueData' must be set");
    }

    if (fingerprint == null) {
      throw new IllegalArgumentException("'fingerprint' must be set");
    }

    if (!(validFromTimestamp < validToTimestamp)) {
      throw new IllegalArgumentException(
          "validity timestamps are invalid, 'validFromTimestamp' "
          + "must be smaller than 'validToTimestamp'");
    }

    if (serverName == null || serverName.isEmpty()) {
      throw new IllegalArgumentException("'serverName' must be set and non-empty");
    }

    if (userName == null || userName.isEmpty()) {
      throw new IllegalArgumentException("'userName' must be set and non-empty");
    }

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

  public Fingerprint getFingerprint() {
    return fingerprint;
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

  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Challenge challenge = (Challenge) o;

    return Arrays.equals(uniqueData, challenge.uniqueData)
           && validFromTimestamp == challenge.validFromTimestamp
           && validToTimestamp == challenge.validToTimestamp
           && fingerprint.equals(challenge.fingerprint)
           && serverName.equals(challenge.serverName)
           && userName.equals(challenge.userName);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(uniqueData);
    result = 31 * result + validFromTimestamp;
    result = 31 * result + validToTimestamp;
    result = 31 * result + fingerprint.hashCode();
    result = 31 * result + serverName.hashCode();
    result = 31 * result + userName.hashCode();
    return result;
  }
}
