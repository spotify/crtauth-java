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

import java.util.Arrays;

public class Response {

  private final byte[] payload;
  private final byte[] signature;

  public Response(byte[] payload, byte[] signature) {
    Preconditions.checkNotNull(payload);
    Preconditions.checkNotNull(signature);
    this.payload = payload;
    this.signature = signature;
  }

  public byte[] getPayload() {
    return payload;
  }

  public byte[] getSignature() {
    return Arrays.copyOf(signature, signature.length);
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Response response = (Response) o;
    return Arrays.equals(signature, response.signature)
           && Arrays.equals(payload, response.payload);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(signature);
    result = 31 * result + Arrays.hashCode(payload);
    return result;
  }
}
