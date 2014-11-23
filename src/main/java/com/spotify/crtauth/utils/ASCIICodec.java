/*
 * Copyright (c) 2014 Spotify AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/license/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.spotify.crtauth.utils;

import com.google.common.io.BaseEncoding;

/**
 * Utility class to encode and decode binary data in to URL compatible ASCII.
 */
public class ASCIICodec {
  private static final BaseEncoding encoding = BaseEncoding.base64Url();

  public static String encode(byte[] data) {
    return encoding.encode(data).replaceAll("=", "");
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
