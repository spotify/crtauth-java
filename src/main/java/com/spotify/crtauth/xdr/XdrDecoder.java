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

/**
 * This interface represents a decoder of XDR-encoded binary blobs. It supports a subset of the
 * data types described in RFC 4506.
 */
public interface XdrDecoder {
  /**
   * Decode and return a string encoded as described in RFC 5506, Section 4.11.
   * @return The string data.
   * @throws IOException if anything goes wrong (for example, if trying to read data that doesn't
   *    represent a string or if trying to read data from a non-aligned buffer position).
   */
  public String readString() throws IOException;
  /**
   * Decode and return a fixed length string. This data type is not defined in RFC 4506,
   * so this method can be seen as a convenience method that reads a fix-length blob of opaque
   * data and encodes it as a US-ASCII string.
   * @return The string data.
   * @throws IOException if anything goes wrong (for example, if trying to read data that doesn't
   *    represent a string or if trying to read data from a non-aligned buffer position).
   */
  public String readFixedLengthString(int length) throws IOException;
  /**
   * Decode and return a fixed length blob of opaque data. This data type is defined in RFC 4506,
   * Section 4.9.
   * @return A blob of binary data.
   * @throws IOException if anything goes wrong (for example, if trying to read data that doesn't
   *    represent a string or if trying to read data from a non-aligned buffer position).
   */
  public byte[] readFixedLengthOpaque(int length) throws IOException;
  /**
   * Decode and return a fixed length blob of opaque data. This data type is defined in RFC 4506,
   * Section 4.10.
   * @return A blob of binary data.
   * @throws IOException if anything goes wrong (for example, if trying to read data that doesn't
   *    represent a string or if trying to read data from a non-aligned buffer position).
   */
  public byte[] readVariableLengthOpaque() throws IOException;
  /**
   * Decode and return an integer number. This data type is defined in RFC 4506, 4.1.
   * @return A 32-bit integer.
   * @throws IOException if anything goes wrong (for example, if trying to read data that doesn't
   *    represent a string or if trying to read data from a non-aligned buffer position).
   */
  public int readInt() throws IOException;
}
