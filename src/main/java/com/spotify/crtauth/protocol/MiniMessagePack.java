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

import com.google.common.base.Charsets;
import com.google.common.io.ByteStreams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * This class implements the needed subset of the draft msgpack specification as available at
 * https://github.com/msgpack/msgpack/blob/7498cf31d1110170e4901d47951fe880d169f327/spec.md
 *
 * When a stable implementation of this specification exists, please consider switching an
 * externally maintained version.
 */
class MiniMessagePack {

  public static class Packer {

    private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    private final DataOutputStream dataOutput = new DataOutputStream(byteArrayOutputStream);

    /**
     * Pack an integer in msgpack format. Negative values are not supported at the moment.
     *
     * @param integer a positive integer
     */
    public void pack(int integer) {
      checkArgument(integer >= 0, "Negative integers not supported at the moment");
      try {
        if (integer < 1 << 7) {
          dataOutput.writeByte(integer);
        } else if (integer < 1 << 8) {
          dataOutput.writeByte((byte) 0xcc);
          dataOutput.writeByte(integer);
        } else if (integer < 1 << 16) {
          dataOutput.writeByte((byte) 0xcd);
          dataOutput.writeShort(integer);
        } else {
          dataOutput.writeByte((byte) 0xce);
          dataOutput.writeInt(integer);
        }
      } catch (IOException e) {
        throw new RuntimeException("Filed to write to buffer. Should not happen", e);
      }
    }

    /**
     * Pack an array of bytes in msgpack format.
     *
     * @param data an array of bytes to pack.
     */
    public void pack(byte[] data) {
      checkNotNull(data);
      try {
        if (data.length < 1 << 8) {
          dataOutput.write(0xc4);
          dataOutput.writeByte(data.length);
        } else if (data.length < 1 << 16) {
          dataOutput.write(0xc5);
          dataOutput.writeShort(data.length);
        } else {
          dataOutput.write(0xc6);
          dataOutput.writeInt(data.length);
        }
        dataOutput.write(data);
      } catch (IOException e) {
        throw new RuntimeException("Filed to write to buffer. Should not happen", e);
      }
    }

    /**
     * Pack a String in msgpack format.
     *
     * @param data a String to pack.
     */
    public void pack(String data) {
      checkNotNull(data);
      byte[] encoded = data.getBytes(Charsets.UTF_8);
      try {
        if (encoded.length < 1 << 5) {
          dataOutput.write(0xa0 | encoded.length);
        } else if (data.length() < 1 << 8) {
          dataOutput.write(0xd9);
          dataOutput.writeByte(encoded.length);
        } else if (data.length() < 1 << 16) {
          dataOutput.write(0xda);
          dataOutput.writeShort(encoded.length);
        } else {
          dataOutput.write(0xdb);
          dataOutput.writeInt(encoded.length);
        }
        dataOutput.write(encoded);
      } catch (IOException e) {
        throw new RuntimeException("Filed to write to buffer. Should not happen", e);
      }
    }


    /**
     * Gets the bytes of everything packed in this Packer so far.
     *
     * @return an array of bytes
     */
    public byte[] getBytes() {
      return byteArrayOutputStream.toByteArray();
    }
  }

  public static class Unpacker {

    private final DataInputStream dataInputStream;
    private final ByteArrayInputStream byteArrayInputStream;
    final int dataSize;

    public Unpacker(byte[] data) {
      byteArrayInputStream = new ByteArrayInputStream(data);
      dataInputStream = new DataInputStream(byteArrayInputStream);
      dataSize = data.length;
    }

    /**
     * Unpacks and returns an int from this Unpacker. Negative integers are not yet supported.
     *
     * @return the int we read.
     */
    public int unpackInt() throws DeserializationException {
      try {
        int firstByte = readByte(dataInputStream);
        if (firstByte < 0x80) {
          return firstByte;
        } else if (firstByte == 0xcc) {
          return readByte(dataInputStream);
        } else if (firstByte == 0xcd) {
          // readShort() reads a signed short, which won't do in this case
          return readByte(dataInputStream) << 8 | readByte(dataInputStream);
        } else if (firstByte == 0xce) {
          int ret = dataInputStream.readInt();
          if (ret < 0) {
            throw new DeserializationException(
                "Attempting to deserialize an integer larger than Integer.MAX_VALUE"
            );
          }
          return ret;
        } else {
          throw new DeserializationException(String.format(
              "Attempted to read int but initial byte (0x%02x) indicates non-integer",
              firstByte
          ));
        }
      } catch (IOException e) {
        throw new DeserializationException("Attempted to read past end of buffer");
      }
    }

    /**
     * Unpacks and returns a byte array from this Unpacker instance.
     *
     * @return a byte array with binary data
     * @throws DeserializationException if an attempt to read past the end of the internal buffer or
     *                                  if the data read is not marked as in the bin family
     */
    public byte[] unpackBin() throws DeserializationException {
      try {
        int firstByte = readByte(dataInputStream);
        int len;
        if (firstByte == 0xc4) {
          len = readByte(dataInputStream);
        } else if (firstByte == 0xc5) {
          len = readByte(dataInputStream) << 8 | readByte(dataInputStream);
        } else if (firstByte == 0xc6) {
          len = dataInputStream.readInt();
          if (len < 0) {
            throw new DeserializationException(
                "Attempting to deserialize an bin longer than Integer.MAX_VALUE"
            );
          }
        } else {
          throw new DeserializationException(String.format(
              "Attempted to read int initial byte (0x%02x) indicates non-bin type",
              firstByte
          ));
        }
        byte[] data = new byte[len];
        ByteStreams.readFully(dataInputStream, data);
        return data;
      } catch (IOException e) {
        throw new DeserializationException("Attempted to read past end of buffer");
      }
    }

    /**
     * Unpacks and returns a String read from this unpacker.
     *
     * @return returns a String
     * @throws DeserializationException if the read data is not possible to decode as UTF-8, or if
     *                                  the buffer is too small, or if the data decoded is not
     *                                  described as String
     */
    public String unpackString() throws DeserializationException {
      try {
        final int firstByte = readByte(dataInputStream);
        final int len;
        if (firstByte > 0x9f && firstByte < 0xc0) {
          len = firstByte & 0x1f;
        } else if (firstByte == 0xd9) {
          len = readByte(dataInputStream);
        } else if (firstByte == 0xda) {
          len = readByte(dataInputStream) << 8 | readByte(dataInputStream);
        } else if (firstByte == 0xdb) {
          len = dataInputStream.readInt();
          if (len < 0) {
            throw new DeserializationException(
                "Attempting to deserialize an str longer than Integer.MAX_VALUE"
            );
          }
        } else {
          throw new DeserializationException(String.format(
              "Attempted to read int initial byte (0x%02x) indicates non-str type",
              firstByte
          ));
        }
        byte[] encodedString = new byte[len];
        ByteStreams.readFully(dataInputStream, encodedString);
        return new String(encodedString, Charsets.UTF_8);
      } catch (IOException e) {
        throw new DeserializationException("Attempted to read past end of buffer");
      }
    }

    /**
     * Unpack an int and return it cast to a java byte (which is signed), throwing an exception if
     * the integer unpacked is too large to fit.
     *
     * @return an unpacked byte
     * @throws DeserializationException if the read int is too big.
     */
    public byte unpackByte() throws DeserializationException {
      int i = unpackInt();
      if (i > 0xff) {
        throw new DeserializationException("Expected unsigned int < 0xff");
      }
      return (byte) i;
    }


    /**
     * Wraps InputStream.read() and throws Deserialization exception when EOF is reached
     *
     * @param inputStream the InputStream to read from
     * @return an unsigned byte, stored in an int
     * @throws IOException              if the read fails
     * @throws DeserializationException if end of file is reached
     */
    private static int readByte(InputStream inputStream)
        throws IOException, DeserializationException {
      final int i = inputStream.read();
      if (i == -1) {
        throw new DeserializationException("Attempted to read past end of buffer");
      }
      return i;
    }

    /**
     * Indicates whether end of stream has been reached or not. Used for testing
     *
     * @return true if end of stream is reached, else false
     */
    boolean bytesLeft() {
      return byteArrayInputStream.available() > 0;
    }

    public int getBytesRead() {
      return dataSize - byteArrayInputStream.available();
    }
  }
}
