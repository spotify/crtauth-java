package com.spotify.crtauth;

import com.google.common.io.BaseEncoding;

/**
 * Utility class to encode and decode binary data in to URL compatible ASCII.
 */
class ASCIICodec {
  private static BaseEncoding encoding = BaseEncoding.base64Url();

  public static String encode(byte[] data) {
    return encoding.encode(data);
  }

  public static byte[] decode(String encoded) {
    try {
      return encoding.decode(encoded);
    } catch (IllegalArgumentException e) {
      Throwable t = e;
      if (e.getCause() instanceof BaseEncoding.DecodingException) {
        t = e.getCause();
      }
      throw new IllegalArgumentException(String.format("Failed to decode String '%s'", encoded), t);
    }
  }
}
