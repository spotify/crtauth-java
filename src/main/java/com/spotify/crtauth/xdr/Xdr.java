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

import com.google.common.base.Charsets;
import com.spotify.crtauth.exceptions.DataOutOfBoundException;
import com.spotify.crtauth.exceptions.IllegalAsciiString;
import com.spotify.crtauth.exceptions.IllegalLengthException;
import com.spotify.crtauth.exceptions.XdrException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

/**
 * This class implements XDR encoding for a subset of the data types defined in RFC-4506. This
 * class can't be instantiated directly, instead a {@code newEncoder} and {@code newDecoder}
 * factory methods are provided.
 * The maximum size of serialized data handled by this implementation is 512 KB.
 */
public class Xdr implements XdrEncoder, XdrDecoder {
  // The size of the maximum payload we're able to serialize. There is no such value mandated by
  // RFC-4506, but 512KB should be more than enough for anything we need to do.
  private final static int MAX_XDR_SIZE = 512 * 1024;
  private final static int BYTE_SIZE = Byte.SIZE;
  // Data is aligned over 4-byte block boundaries.
  private final static int BLOCK_SIZE = 4;
  private final ByteBuffer byteBuffer;

  public static XdrEncoder newEncoder() {
    ByteBuffer buffer = ByteBuffer.allocate(MAX_XDR_SIZE);
    return new Xdr(buffer);
  }

  public static XdrDecoder newDecoder(byte[] data) {
    checkArgument(data.length <= MAX_XDR_SIZE);
    ByteBuffer buffer = ByteBuffer.wrap(data);
    return new Xdr(buffer);
  }

  private Xdr(ByteBuffer byteBuffer) {
    this.byteBuffer = byteBuffer;
    this.byteBuffer.order(ByteOrder.BIG_ENDIAN);
  }

  /**
   * Write a number of null bytes so that the buffer pointer is aligned over the next 4-byte block.
   * This method should be invoked after writing any type, in order to pad the buffer with the
   * appropriate number of bytes, if necessary.
   */
  private void pad() {
    int position = byteBuffer.position();
    int mod = position % BLOCK_SIZE;
    if (mod != 0) {
      // We need padding to fill the last block
      pad(BLOCK_SIZE - mod);
    }
  }

  /**
   * Pad the buffer with `lenght' null bytes.
   * @param lenght The number of null bytes to be appended to the buffer.
   */
  private void pad(int lenght) {
    for (int i = 0; i < lenght; ++i) {
      byteBuffer.put((byte) 0);
    }
  }

  @Override
  public String readString() throws XdrException {
    // In theory, this value is an unsigned int. In practice we support at most 512KB sequences, so
    // we'll just consider it as a normal integer.
    assertAligned();
    int length = byteBuffer.getInt();
    byte[] rawBytes = readRawBytes(length);
    align();
    return new String(rawBytes, Charsets.US_ASCII);
  }

  @Override
  public String readFixedLengthString(int length) throws XdrException {
    assertAligned();
    byte[] rawBytes = readRawBytes(length);
    align();
    return new String(rawBytes, Charsets.US_ASCII);
  }

  @Override
  public byte[] readFixedLengthOpaque(int length) throws XdrException {
    assertAligned();
    byte[] rawBytes = readRawBytes(length);
    align();
    return rawBytes;
  }

  @Override
  public byte[] readVariableLengthOpaque() throws XdrException {
    assertAligned();
    int length = readInt();
    byte[] rawBytes = readRawBytes(length);
    align();
    return rawBytes;
  }

  @Override
  public int readInt() throws XdrException {
    assertAligned();
    int read = byteBuffer.getInt();
    int finalPosition = byteBuffer.position();
    align();
    // Align shouldn't have any effect since an int is always 1 block long, as per specification.
    checkState(finalPosition == byteBuffer.position());
    return read;
  }

  private byte[] readRawBytes(int length) throws XdrException {
    if (length < 0) {
      throw new IllegalLengthException();
    }
    if (remaniningBytes() < length) {
      throw new DataOutOfBoundException();
    }
    byte[] rawBytes = new byte[length];
    try {
      byteBuffer.get(rawBytes, 0, length);
    } catch (Exception e) {
      throw new DataOutOfBoundException(e);
    }
    return rawBytes;
  }

  /**
   * Return the number of bytes the are left in the buffer, from the current position.
   * @return The number of bytes that can be read
   */
  public int remaniningBytes() {
    return byteBuffer.limit() - byteBuffer.position();
  }

  private void assertAligned() {
    int offset = byteBuffer.position() % BLOCK_SIZE;
    checkState(offset == 0, "Reading from a non-aligned location.");
  }

  private void align() {
    int skip = (BLOCK_SIZE - (byteBuffer.position() % BLOCK_SIZE)) % BLOCK_SIZE;
    if (remaniningBytes() < skip) {
      // The last block has been read. There is no need to align again.
      return;
    }
    byteBuffer.position(byteBuffer.position() + skip);
  }

  @Override
  public void writeString(String string) throws XdrException {
    byte[] rawBytes = string.getBytes(Charsets.US_ASCII);
    if (rawBytes.length != string.length()) {
      throw new IllegalAsciiString();
    }
    if (rawBytes.length + 1 > remaniningBytes()) {
      throw new DataOutOfBoundException();
    }
    assertAligned();
    byteBuffer.putInt(rawBytes.length);
    byteBuffer.put(rawBytes);
    pad();
  }

  @Override
  public void writeFixedLengthString(int length, String string) throws XdrException {
    byte[] rawBytes = string.getBytes(Charsets.US_ASCII);
    if (rawBytes.length != string.length()) {
      throw new IllegalAsciiString();
    }
    assertAligned();
    writeRawBytes(length, rawBytes);
    pad();
  }

  @Override
  public void writeFixedLengthOpaque(int length, byte[] bytes) throws XdrException {
    assertAligned();
    writeRawBytes(length, bytes);
    pad();
  }

  @Override
  public void writeVariableLengthOpaque(byte[] bytes) throws XdrException {
    int length = bytes.length;
    assertAligned();
    byteBuffer.putInt(length);
    writeRawBytes(length, bytes);
    pad();
  }

  @Override
  public void writeInt(int integer) throws XdrException {
    assertAligned();
    byteBuffer.putInt(integer);
    int finalPosition = byteBuffer.position();
    pad();
    checkState(finalPosition == byteBuffer.position());
  }

  private void writeRawBytes(int length, byte[] rawBytes) throws XdrException {
    if (length > remaniningBytes()) {
      throw new DataOutOfBoundException();
    }
    if (rawBytes.length > length) {
      rawBytes = Arrays.copyOf(rawBytes, length);
    }
    byteBuffer.put(rawBytes);
    if (rawBytes.length < length) {
      pad(length - rawBytes.length);
    }
    pad();
  }

  @Override
  public byte[] encode() throws XdrException {
    return Arrays.copyOf(byteBuffer.array(), byteBuffer.position());
  }
}
