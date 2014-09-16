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

package com.spotify.crtauth.digest;

/**
 * This interface represent a plug-in message digest algorithm, that returns a digest given a
 * byte blob as an input.
 */
public interface DigestAlgorithm {
  public static final int DIGEST_LENGTH = 20;
  /**
   * Return a message digest of size DIGEST_LENGTH.
   * @param data The input data, as a binary array.
   * @return The digest.
   */
  public byte[] getDigest(byte[] data);
}
