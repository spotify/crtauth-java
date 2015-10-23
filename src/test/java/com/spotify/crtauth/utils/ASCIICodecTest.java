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

package com.spotify.crtauth.utils;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests ASCIICodec
 */
public class ASCIICodecTest {
  @Test
  public void testEncode() {
    // yes, ugly, but 100% test coverage is nice :)
    new ASCIICodec();
    Assert.assertEquals("3q0", ASCIICodec.encode(new byte[] {(byte)0xde, (byte)0xad}));
  }

  @Test
  public void testEncodeURLSensitive() {
    Assert.assertEquals("_-A", ASCIICodec.encode(new byte[] {(byte)0xff, (byte)0xe0}));
  }

  @Test
  public void testDecode() {
    Assert.assertArrayEquals(new byte[] {(byte)0xde, (byte)0xad}, ASCIICodec.decode("3q0"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDecodeInvalidData() {
      ASCIICodec.decode("@");
  }
}
