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
import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.utils.ASCIICodec;
import org.junit.Test;

public class ChallengeTest {

  @Test(expected=IllegalArgumentException.class)
  public void testNegativeValidity() {
    Challenge.newBuilder()
        .setUniqueData(ASCIICodec.decode("dVhGT9Lbf_59f5ORIHZoiUc2H8I="))
        .setFingerprint(new Fingerprint(ASCIICodec.decode("TJoHEsse")))
        .setValidFromTimestamp(UnsignedInteger.valueOf(1365084634).intValue())
        .setValidToTimestamp(UnsignedInteger.valueOf(1365084334).intValue())
        .setServerName("server.example.com")
        .setUserName("username")
        .build();
  }

}
