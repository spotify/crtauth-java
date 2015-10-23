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

import com.spotify.crtauth.utils.SettableTimeSupplier;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TokenTest {
  private static final int DEFAULT_VALID_FROM = 1365084334;
  private static final int DEFAULT_VALID_TO = 1365084634;


  @Test
  public void testTokenIsNotExpired() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    for (int time = DEFAULT_VALID_FROM; time <= DEFAULT_VALID_TO; ++time) {
      timeSupplier.setTime(DEFAULT_VALID_FROM);
      assertFalse(CrtAuthCodecTest.TOKEN.isExpired(timeSupplier));
    }
  }

  @Test
  public void testTokenNotValid() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_FROM - 1);
    assertTrue(CrtAuthCodecTest.TOKEN.isExpired(timeSupplier));
  }

  @Test
  public void testTokenExpired() {
    SettableTimeSupplier timeSupplier = new SettableTimeSupplier();
    timeSupplier.setTime(DEFAULT_VALID_TO + 1);
    assertTrue(CrtAuthCodecTest.TOKEN.isExpired(timeSupplier));
  }
}
