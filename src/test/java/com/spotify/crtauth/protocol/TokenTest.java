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
import com.spotify.crtauth.utils.SettableTimeSupplier;
import org.junit.Test;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class TokenTest extends XdrSerializableTest<Token> {
  private static final int DEFAULT_VALID_FROM = 10;
  private static final int DEFAULT_VALID_TO = 20;

  public static Token getDefaultToken() {
    return Token.newBuilder()
        .setUserName("spotify")
        .setValidFrom(DEFAULT_VALID_FROM)
        .setValidTo(DEFAULT_VALID_TO)
        .build();
  }

  @Override
  protected Token getInstance() {
    return getDefaultToken();
  }

  @Test
  public void testSerializeToken() throws Exception {
    final String expected = "dAAAAFFdiK5RXYnaAAAAA25vYQA=";
    Token token = new Token.Builder()
        .setUserName("noa")
        .setValidFrom(UnsignedInteger.valueOf(1365084334).intValue())
        .setValidTo(UnsignedInteger.valueOf(1365084634).intValue())
        .build();
    assertArrayEquals(token.serialize(), BaseEncoding.base64().decode(expected));
  }

  @Test
  public void testDeserializeToken() throws Exception {
    final String encoded = "dAAAAFFdixdRXYtVAAAABHRlc3Q=";
    Token token = Token.getDefaultInstance().deserialize(BaseEncoding.base64().decode(encoded));
    assertEquals(token.getUserName(), "test");
    assertEquals(token.getValidFrom(), UnsignedInteger.valueOf(1365084951).intValue());
  }

  @Test
  public void testTokenIsNotExpired() {
    Token token = getDefaultToken();
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    for (int time = DEFAULT_VALID_FROM; time <= DEFAULT_VALID_TO; ++time) {
      timeSupplier.setTime(DEFAULT_VALID_FROM);
      assertFalse(token.isExpired(timeSupplier));
    }
  }

  @Test
  public void testTokenNotValid() {
    Token token = getDefaultToken();
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_FROM - 1);
    assertTrue(token.isExpired(timeSupplier));
  }

  @Test
  public void testTokenExpired() {
    Token token = getDefaultToken();
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_TO + 1);
    assertTrue(token.isExpired(timeSupplier));
  }

}
