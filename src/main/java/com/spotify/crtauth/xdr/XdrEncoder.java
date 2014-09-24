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

import java.io.IOException;

import com.spotify.crtauth.exceptions.XdrException;

/**
 * This interface represents an XDR encoder. It supports a subset of the data types described in
 * RFC 4506. The XDR Encoder encodes data sequentially, and return a binary representation of the
 * data that has been previously encoded when invoking the {@code encode} method.
 */
public interface XdrEncoder {
  /**
   * Encode a String as described in RFC 5506, Section 4.11.
   * @param string The string data.
   * @throws IOException If anything goes wrong.
   */
  public void writeString(String string) throws XdrException;

  /**
   * Encode a fixed length string. This data type is not defined in RFC 4506,
   * so this method can be seen as a convenience method that transforms a String into a
   * byte blob by applying US-ASCII encoding, and writes the result as fixed length opaque data.
   * @param length The length of the string. If the actual string is longer than the specified
   *    length, it will be trimmed. If the actual string is shorter than the specified length,
   *    it will be padded with null bytes.
   * @param string The string data.
   * @throws IOException If anything goes wrong.
   */
  public void writeFixedLengthString(int length, String string)
      throws XdrException;

  /**
   * Encode a fixed length blob of binary data. This data type is defined in RFC 4506,
   * Section 4.9.
   * @param length The length of the byte blob. If the actual byte blob is longer than the
   *    specified length, it will be trimmed. If the actual blob is shorter than the specified
   *    length, it will be padded with null bytes.
   * @param bytes A byte blob.
   * @throws IOException If anything goes wrong.
   */
  public void writeFixedLengthOpaque(int length, byte[] bytes)
      throws XdrException;

  /**
   * Encode a variable length blob of opaque data. This data type is defined in RFC 4506,
   * Section 4.10.
   * @param bytes A byte blob.
   * @throws IOException If anything goes wrong.
   */
  public void writeVariableLengthOpaque(byte[] bytes) throws XdrException;

  /**
   * Encode an integer number. This data type is defined in RFC 4506, 4.1.
   * @param integer A 32-bit integer.
   * @throws IOException If anything goes wrong.
   */
  public void writeInt(int integer) throws XdrException;

  /**
   * Return a serialized representation of whatever has been written to the {@code XdrEncoder}.
   * @return The RFC 4506-compliant representation of the XdrEncoder content, as a byte array.
   * @throws IOException If anything goes wrong.
   */
  public byte[] encode() throws XdrException;
}
