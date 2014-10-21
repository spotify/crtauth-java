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

import com.spotify.crtauth.ASCIICodec;
import com.spotify.crtauth.digest.DigestAlgorithm;
import com.spotify.crtauth.digest.MessageHashDigestAlgorithm;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.utils.SettableTimeSupplier;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TokenTest {
  private static final int DEFAULT_VALID_FROM = 1365084334;
  private static final int DEFAULT_VALID_TO = 1365084634;

  private static final byte[] ENCODED_TOKEN = ASCIICodec.decode(
      "AXTOUV2Irs5RXYnao25vYcQgKVlUyZneScS57Xwk2syvL0GTQhV0FF9ciWQZYluN4m8="
  );

  private static final Token TOKEN = new Token(1365084334, 1365084634, "noa");

  @Test
  public void testSerializeToken() throws Exception {
    assertArrayEquals(TOKEN.serialize("gurkburk".getBytes()), ENCODED_TOKEN);
  }

  @Test
  public void testDeserializeToken() throws Exception {
    Token token = Token.deserialize(ENCODED_TOKEN);
    Assert.assertEquals(TOKEN, token);
  }

  @Test
  public void testTokenIsNotExpired() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    for (int time = DEFAULT_VALID_FROM; time <= DEFAULT_VALID_TO; ++time) {
      timeSupplier.setTime(DEFAULT_VALID_FROM);
      assertFalse(TOKEN.isExpired(timeSupplier));
    }
  }

  @Test
  public void testTokenNotValid() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_FROM - 1);
    assertTrue(TOKEN.isExpired(timeSupplier));
  }

  @Test
  public void testTokenExpired() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_TO + 1);
    assertTrue(TOKEN.isExpired(timeSupplier));
  }

  @Test
  public void testDeserializeAuthenticated() throws Exception {
    Token.deserializeAuthenticated(ENCODED_TOKEN, "gurkburk".getBytes());
  }

  @Test(expected = InvalidInputException.class)
  public void testDeserializeAuthenticatedCorrupt() throws Exception {
    byte[] mine = Arrays.copyOf(ENCODED_TOKEN, ENCODED_TOKEN.length);
    mine[mine.length - 4] = 't';
    Token.deserializeAuthenticated(mine, "gurkburk".getBytes());
  }
}
