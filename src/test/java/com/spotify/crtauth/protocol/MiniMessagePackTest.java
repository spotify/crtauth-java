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

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Tests MiniMessagePack
 */
public class MiniMessagePackTest {

  @Test(expected = IllegalArgumentException.class)
  public void testPackNegativeInt() {
    new MiniMessagePack.Packer().pack(-1);
  }

  @Test
  public void testPackInt() {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(0x2a);
    compare(packer, false, 0x2a);

    packer = new MiniMessagePack.Packer();
    packer.pack((1<<8) - 1);
    compare(packer, false, 0xcc, 0xff);

    packer = new MiniMessagePack.Packer();
    packer.pack(1<<8);
    compare(packer, false, 0xcd, 0x01, 0x00);

    packer = new MiniMessagePack.Packer();
    packer.pack((1<<16)-1);
    compare(packer, false, 0xcd, 0xff, 0xff);

    packer = new MiniMessagePack.Packer();
    packer.pack(1<<16);
    compare(packer, false, 0xce, 0x00, 0x01, 0x00, 0x00);

    packer = new MiniMessagePack.Packer();
    packer.pack(Integer.MAX_VALUE);
    compare(packer, false, 0xce, 0x7f, 0xff, 0xff, 0xff);
  }

  @Test
  public void testPackBin() {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack(new byte[] {(byte)0xbe, (byte)0xef});
    compare(packer, false, 0xc4, 0x02, 0xbe, 0xef);

    packer = new MiniMessagePack.Packer();
    packer.pack(new byte[0x100]);
    Assert.assertEquals(0x100 + 3, packer.getBytes().length);
    compare(packer, true, 0xc5, 0x01, 0x00, 0x00);

    packer = new MiniMessagePack.Packer();
    packer.pack(new byte[0x10000]);
    Assert.assertEquals(0x10000 + 5, packer.getBytes().length);
    compare(packer, true, 0xc6, 0x00, 0x01, 0x00, 0x00);
  }

  @Test
  public void testPackStr() {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack("€");
    compare(packer, false, 0xa3, 0xe2, 0x82, 0xac);

    packer = new MiniMessagePack.Packer();
    packer.pack(makeString(31));
    Assert.assertEquals(32, packer.getBytes().length);
    compare(packer, true, 0xbf, 0x61);

    packer = new MiniMessagePack.Packer();
    packer.pack(makeString(32));
    Assert.assertEquals(34, packer.getBytes().length);
    compare(packer, true, 0xd9, 0x20, 0x61);

    packer = new MiniMessagePack.Packer();
    packer.pack(makeString(0x100));
    Assert.assertEquals(0x103, packer.getBytes().length);
    compare(packer, true, 0xda, 0x01, 0x00, 0x61);

    packer = new MiniMessagePack.Packer();
    packer.pack(makeString(0x10000));
    Assert.assertEquals(0x10005, packer.getBytes().length);
    compare(packer, true, 0xdb, 0x00, 0x01, 0x00, 0x00, 0x61);
  }

  @Test
  public void testUnpackInt() throws Exception {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(42));
    Assert.assertEquals(42, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0x7f, 0x00));
    Assert.assertEquals(0x7f, unpacker.unpackInt());
    Assert.assertTrue(unpacker.bytesLeft());
    Assert.assertEquals(0, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xcc, 0x80));
    Assert.assertEquals(0x80, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xcc, 0xff));
    Assert.assertEquals(0xff, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xcd, 0x01, 0x00));
    Assert.assertEquals(0x100, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xcd, 0xff, 0xff));
    Assert.assertEquals(0xffff, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xce, 0x00, 0x01, 0x00, 0x00));
    Assert.assertEquals(0x10000, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());

    unpacker = new MiniMessagePack.Unpacker(byteArray(0xce, 0x00, 0x01, 0x00, 0x00));
    Assert.assertEquals(0x10000, unpacker.unpackInt());
    Assert.assertFalse(unpacker.bytesLeft());
  }

  @Test(expected = DeserializationException.class)
  public void testReadStringAsInt() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0x0a1, 0x61));
    unpacker.unpackInt();
  }

  @Test(expected = DeserializationException.class)
  public void testReadAsIntPastEnd() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0x42));
    unpacker.unpackInt();
    unpacker.unpackInt();
  }

  @Test(expected = DeserializationException.class)
  public void testShortReadFromFourByteInt() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xce, 0x00));
    unpacker.unpackInt();
  }

  @Test(expected = DeserializationException.class)
  public void testReadTooLargeUnsigned() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xce, 255, 0, 0, 0));
    unpacker.unpackInt();
  }

  @Test
  public void testReadBin() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xc4, 0x01, 0x00));
    Assert.assertArrayEquals(byteArray(0x00), unpacker.unpackBin());

    byte[] toUnpack = new byte[(1<<8) + 3];
    toUnpack[0] = (byte)0xc5;
    toUnpack[1] = (byte)0x01;
    unpacker = new MiniMessagePack.Unpacker(toUnpack);
    Assert.assertArrayEquals(new byte[1<<8], unpacker.unpackBin());

    toUnpack = new byte[(1<<16) + 5];
    toUnpack[0] = (byte)0xc6;
    toUnpack[2] = (byte)0x01;
    unpacker = new MiniMessagePack.Unpacker(toUnpack);
    Assert.assertArrayEquals(new byte[1<<16], unpacker.unpackBin());
  }

  @Test
  public void testReadStr() throws DeserializationException {
    byte[] data = byteArray(0xa3, 0xe2, 0x82, 0xac);
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals("€", unpacker.unpackString());

    data = new byte[32];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xbf;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString(31), unpacker.unpackString());

    data = new byte[34];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xd9;
    data[1] = (byte)0x20;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString(32), unpacker.unpackString());

    data = new byte[257];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xd9;
    data[1] = (byte)0xff;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString(255), unpacker.unpackString());

    data = new byte[(1<<8) + 3];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xda;
    data[1] = (byte)0x01;
    data[2] = (byte)0x00;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString(256), unpacker.unpackString());

    data = new byte[(1<<16) + 2];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xda;
    data[1] = (byte)0xff;
    data[2] = (byte)0xff;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString((1<<16)-1), unpacker.unpackString());

    data = new byte[(1<<16) + 5];
    Arrays.fill(data, (byte)0x61);
    data[0] = (byte)0xdb;
    data[1] = (byte)0x00;
    data[2] = (byte)0x01;
    data[3] = (byte)0x00;
    data[4] = (byte)0x00;
    unpacker = new MiniMessagePack.Unpacker(data);
    Assert.assertEquals(makeString(1<<16), unpacker.unpackString());
  }


  @Test(expected = DeserializationException.class)
  public void testReadAsStringPastEnd() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0x42));
    unpacker.unpackInt();
    unpacker.unpackString();
  }

  @Test(expected = DeserializationException.class)
  public void testShortReadFromFourByteIntString() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xdb, 0x00));
    unpacker.unpackString();
  }

  @Test(expected = DeserializationException.class)
  public void testReadTooLargeUnsignedStr() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xdb, 255, 0, 0, 0));
    unpacker.unpackString();
  }

  @Test(expected = DeserializationException.class)
  public void testReadIntAsString() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(42));
    unpacker.unpackString();
  }

  @Test(expected = DeserializationException.class)
  public void testReadIntAsBin() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(42));
    unpacker.unpackBin();
  }

  @Test(expected = DeserializationException.class)
  public void testReadTooLargeUnsignedBin() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xc6, 255, 0, 0, 0));
    unpacker.unpackBin();
  }

  @Test(expected = DeserializationException.class)
  public void testShortReadFromFourByteIntBin() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xc6, 0x00));
    unpacker.unpackBin();
  }

  @Test
  public void testGetBytesRead() throws DeserializationException {
    byte[] data = byteArray(0xa3, 0xe2, 0x82, 0xac, 42);
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    unpacker.unpackString();
    Assert.assertEquals(4, unpacker.getBytesRead());
  }

  @Test
  public void testUnpackByte() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(42));
    Assert.assertEquals((byte)42, unpacker.unpackByte());
    unpacker = new MiniMessagePack.Unpacker(byteArray(0xcc, 0xff));
    Assert.assertEquals((byte)0xff, unpacker.unpackByte());
  }

  @Test (expected=DeserializationException.class)
  public void testUnpackByteTooLarge() throws DeserializationException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(byteArray(0xcd, 0x01, 0));
    unpacker.unpackByte();

  }

  private static String makeString(int len) {
    byte[] data = new byte[len];
    Arrays.fill(data, (byte)0x61);
    return new String(data);
  }

  private void compare(MiniMessagePack.Packer packer, boolean test_prefix, int... bytes) {
    byte[] packedData = packer.getBytes();
    if (!test_prefix) {
      Assert.assertEquals("Wrong length of packed data", bytes.length, packedData.length);
    }
    for (int i = 0; i < bytes.length; i++) {
      Assert.assertEquals(String.format("Wrong byte at pos %d", i), bytes[i], pos(packedData[i]));
    }
  }

  private static int pos(byte b) {
    return b < 0 ? b + 0x100 : b;
  }

  private static byte[] byteArray(int ... bytes) {
    byte[] output = new byte[bytes.length];
    for (int i = 0; i < bytes.length; i++) {
      output[i] = (byte)bytes[i];
    }
    return output;
  }
}
