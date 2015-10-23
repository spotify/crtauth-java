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

import com.google.common.base.Preconditions;

import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;

public class Token {

  private static final byte MAGIC = 't';

  private final int validFrom;
  private final int validTo;
  private final String userName;

  public Token(int validFrom, int validTo, String userName) {
    Preconditions.checkArgument(validFrom < validTo, "negative lifespan of Token");
    Preconditions.checkNotNull(userName);
    Preconditions.checkArgument(!userName.isEmpty(), "Field 'userName' can not be empty");
    this.validFrom = validFrom;
    this.validTo = validTo;
    this.userName = userName;
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
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Token token = (Token) o;

    if (validFrom != token.validFrom) {
      return false;
    }
    if (validTo != token.validTo) {
      return false;
    }
    return userName.equals(token.userName);

  }

  @Override
  public int hashCode() {
    int result = validFrom;
    result = 31 * result + validTo;
    result = 31 * result + userName.hashCode();
    return result;
  }
}
