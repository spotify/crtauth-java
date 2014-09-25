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

import com.spotify.crtauth.exceptions.DataOutOfBoundException;
import com.spotify.crtauth.exceptions.IllegalAsciiString;
import com.spotify.crtauth.exceptions.IllegalLengthException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;

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

  @Test
  // the idea here is to verify that we are really big endian, reading and writing.
  public void testIntEndian() throws Exception {
    byte[] data = new byte[] { (byte)0, (byte)0, (byte)4, (byte)0 };
    XdrDecoder xdr = Xdr.newDecoder(data);
    Assert.assertEquals(1024, xdr.readInt());

    encoder.writeInt(512);
    Assert.assertArrayEquals(new byte[] {(byte)0, (byte)0, (byte)2, (byte)0}, encoder.encode());
  }

  @Test
  public void testRoundTripFixedString() throws Exception {
    String s = "foobar";
    encoder.writeFixedLengthString(s.length(), s);
    byte[] encoded = encoder.encode();
    XdrDecoder xdr = Xdr.newDecoder(encoded);
    Assert.assertEquals(s, xdr.readFixedLengthString(s.length()));
  }

  @Test
  public void readFixedLengthOpaque() throws Exception {
    byte[] data = "foobar".getBytes();
    encoder.writeFixedLengthOpaque(data.length, data);
    byte[] encoded = encoder.encode();
    XdrDecoder xdr = Xdr.newDecoder(encoded);
    Assert.assertArrayEquals(data, xdr.readFixedLengthOpaque(data.length));
  }

  @Test
  public void readVariableLengthOpaque() throws Exception {
    byte[] data = "foobar".getBytes();
    encoder.writeVariableLengthOpaque(data);
    byte[] encoded = encoder.encode();
    XdrDecoder xdr = Xdr.newDecoder(encoded);
    Assert.assertArrayEquals(data, xdr.readVariableLengthOpaque());
  }

  @Test(expected = DataOutOfBoundException.class)
  public void testLargeWrite() throws Exception {
    byte[] data = new byte[1024 * 1024];
    encoder.writeFixedLengthOpaque(data.length, data);
  }

  @Test
  public void testLowerCountThanInputLength() throws Exception {
    byte[] data = new byte[8];
    Arrays.fill(data, (byte)42);
    encoder.writeFixedLengthOpaque(7, data);
    Assert.assertEquals(0, encoder.encode()[7]);
  }

  //TODO: figure out reasonable semantics for non-ascii
  @Ignore
  @Test(expected = IllegalAsciiString.class)
  // contrary to what one would believe, the ascii encoding happily encodes any Unicode character
  // where things outside US-ASCII encodes as '?'. This should be fixed, at some point.
  public void testInvalidStringInput() throws Exception {
    encoder.writeString("ñ");
  }

  @Test(expected = DataOutOfBoundException.class)
  public void testReadTooMuch() throws Exception {
    byte[] data = new byte[3];
    XdrDecoder decoder = Xdr.newDecoder(data);
    decoder.readFixedLengthOpaque(4);
  }

  @Test
  public void testReadUnalignedLast() throws Exception {
    byte[] data = new byte[3];
    XdrDecoder decoder = Xdr.newDecoder(data);
    decoder.readFixedLengthOpaque(3);
  }

  @Test(expected = IllegalLengthException.class)
  public void testNegativeLengthRead() throws Exception {
    XdrDecoder decoder = Xdr.newDecoder(new byte[0]);
    decoder.readFixedLengthOpaque(-1);
  }
}
