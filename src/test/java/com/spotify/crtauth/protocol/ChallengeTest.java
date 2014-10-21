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
import com.spotify.crtauth.ASCIICodec;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class ChallengeTest {

  public static Challenge getTestChallenge() {
    return Challenge.newBuilder()
        .setUniqueData(ASCIICodec.decode("dVhGT9Lbf_59f5ORIHZoiUc2H8I="))
        .setFingerprint(ASCIICodec.decode("TJoHEsse"))
        .setValidFromTimestamp(UnsignedInteger.valueOf(1365084334).intValue())
        .setValidToTimestamp(UnsignedInteger.valueOf(1365084634).intValue())
        .setServerName("server.example.com")
        .setUserName("username")
        .build();
  }

  // this data is encoded using the python implementation, to ensure binary compatibility
  static final byte[] ENCODED_CHALLENGE =
      ASCIICodec.decode("AWPEFHVYRk_S23_-fX-TkSB2aIlHNh_CzlFdiK7OUV2J2sQGTJoHEssesnNlcnZlci5leG" +
          "FtcGxlLmNvbah1c2VybmFtZcQg9y3oyBv4xUfpPHC9ZcHoj-c1hjHtOj9TSn_jVvv8ELI=");

  @Test
  public void testSerializeChallenge() throws Exception {

    byte[] bytes = getTestChallenge().serialize("secret".getBytes());
    assertArrayEquals(ENCODED_CHALLENGE, bytes);
  }

  @Test
  public void testDeserializeChallenge() throws Exception {
        Challenge challenge = Challenge.deserializeAuthenticated(ENCODED_CHALLENGE, "secret".getBytes());

    assertEquals(getTestChallenge(), challenge);
  }
}
