package com.spotify.crtauth;

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
    Assert.assertEquals("3q0=", ASCIICodec.encode(new byte[] {(byte)0xde, (byte)0xad}));
  }

  @Test
  public void testEncodeURLSensitive() {
    Assert.assertEquals("_-A=", ASCIICodec.encode(new byte[] {(byte)0xff, (byte)0xe0}));
  }

  @Test
  public void testDecode() {
    Assert.assertArrayEquals(new byte[] {(byte)0xde, (byte)0xad}, ASCIICodec.decode("3q0="));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDecodeInvalidData() {
      ASCIICodec.decode("@");
  }
}
