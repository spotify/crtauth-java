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

package com.spotify.crtauth.xdr;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class XdrTest {
  private static final String TEST_STRING = "Wooooooot!";
  private XdrEncoder encoder;

  @Before
  public void setup() {
    encoder = Xdr.newEncoder();
  }

  @Test
  public void testEncodeDecodeString() throws Exception {
    encoder.writeString(TEST_STRING);
    byte[] encoded = encoder.encode();
    XdrDecoder decoder = Xdr.newDecoder(encoded);
    assertEquals(decoder.readString(), TEST_STRING);
  }

  @Test
  public void testEncodeDecodeInt() throws Exception {
    int[] testIntArray = {0, Integer.MAX_VALUE, Integer.MIN_VALUE, -1};
    for (Integer i : testIntArray) {
      encoder.writeInt(i);
    }
    byte[] encoded = encoder.encode();
    XdrDecoder decoder = Xdr.newDecoder(encoded);
    for (Integer expected : testIntArray) {
      int actual = decoder.readInt();
      assertEquals(actual, (int) expected);
    }
  }

}
