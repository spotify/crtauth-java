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

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.UnsignedInteger;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class ChallengeTest extends XdrSerializableTest<Challenge> {
  private static final byte[] DEFAULT_FINGERPRINT = {0, 1, 2, 127, 64, 32};
  private static final int DEFAULT_UNIQUE_DATA_LENGTH = 20;
  private static final byte[] DEFAULT_UNIQUE_DATA = new byte[DEFAULT_UNIQUE_DATA_LENGTH];

  public static Challenge getDefaultChallenge() {
    return Challenge.newBuilder()
        .setFingerprint(DEFAULT_FINGERPRINT)
        .setUniqueData(DEFAULT_UNIQUE_DATA)
        .setServerName("server.spotify.net")
        .setUserName("spotify")
        .setValidFromTimestamp(0)
        .setValidToTimestamp(100)
        .build();
  }

  @Test
  public void testSerializeChallenge() throws Exception {
    final String uniqueData = "hTmeSEvGgz0MLNr3S47D6n06JPg=";
    final String expected = "YwAAAIU5nkhLxoM9DCza90uOw+p9OiT4UV2IrlF74uAAAAAGCQLIfINbAAAAAAALZXhh" +
            "bXBsZS5jb20AAAAABHVzZXI=";
    final String fingerprint = "CQLIfINb";
    BaseEncoding encoding = BaseEncoding.base64();
    Challenge challenge = Challenge.newBuilder()
        .setUniqueData(encoding.decode(uniqueData))
        .setFingerprint(encoding.decode(fingerprint))
        .setValidFromTimestamp(UnsignedInteger.valueOf(1365084334).intValue())
        .setValidToTimestamp(UnsignedInteger.valueOf(1367073504).intValue())
        .setServerName("example.com")
        .setUserName("user")
        .build();
    assertArrayEquals(challenge.serialize(), encoding.decode(expected));
  }

  @Override
  protected Challenge getInstance() {
    return getDefaultChallenge();
  }
}
