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

package com.spotify.crtauth.protocol;

import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.ProtocolVersionException;

/**
 * Tiny static helper for messages parsing.
 */
class MessageParserHelper {
  static void parseVersionMagic(byte magic, MiniMessagePack.Unpacker unpacker)
      throws DeserializationException {

    byte version = unpacker.unpackByte();
    if (version != (byte) 0x01) {
      // version 0 protocol begins with ascii 'v' or ascii 'r'
      if (version == 0x76 || version == 0x72) {
        throw new ProtocolVersionException(
            "Received message using version 0 of the protocol. Only version 1 is supported");
      }
      throw new ProtocolVersionException(
            "Received a message with too new version of the protocol. " +
            "Only version 1 is supported, received version %d" + version
      );
    }
    byte readMagic = unpacker.unpackByte();
    if (readMagic != magic) {
      throw new DeserializationException(String.format(
          "invalid magic byte, expected %d but got %d", readMagic, magic));
    }
  }
}
