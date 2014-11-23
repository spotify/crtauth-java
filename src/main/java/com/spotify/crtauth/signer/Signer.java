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

package com.spotify.crtauth.signer;

import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.exceptions.KeyNotFoundException;

/**
 * This interface wraps a single method to sign a challenge. It's the core component of the
 * CrtAuth client.
 */
public interface Signer {
  /**
   * Sign some binary data using the private key corresponding to the public key with the
   * provided fingerprint.
   *
   *
   * @param data Some data to sign, typically a serialized challenge
   * @return A signature, as a byte array.
   *
   */
  public byte[] sign(byte[] data, Fingerprint fingerprint)
      throws IllegalArgumentException, KeyNotFoundException;
}
