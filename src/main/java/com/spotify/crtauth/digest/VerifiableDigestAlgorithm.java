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

package com.spotify.crtauth.digest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A DigestAlgorithm implementing HMAC using SHA1 as digest algorithm as specified by RFC2104.
 */
public class VerifiableDigestAlgorithm implements DigestAlgorithm {
  private static final String MAC_ALGORITHM = "HmacSHA256";
  private final SecretKeySpec secret;

  public VerifiableDigestAlgorithm(byte[] secret) {
    this.secret = new SecretKeySpec(secret, MAC_ALGORITHM);
  }

  public byte[] getDigest(byte[] data, int offset, int length) {
    try {
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(secret);
      mac.update(data, offset, length);
      return mac.doFinal();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] getDigest(byte[] data) {
    return getDigest(data, 0, data.length);
  }
}
