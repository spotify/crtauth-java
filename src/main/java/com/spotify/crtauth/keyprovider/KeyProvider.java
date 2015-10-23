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

package com.spotify.crtauth.keyprovider;

import com.spotify.crtauth.exceptions.KeyNotFoundException;

import java.security.interfaces.RSAPublicKey;

/**
 * This interface exposes a single method to obtain a key for a given user.
 */
public interface KeyProvider {

  /**
   * Return a public key for the given username.
   *
   * @param username A username as a string.
   * @return The user's public key.
   * @throws KeyNotFoundException when the key is not available. This might happen both because the
   *                              key for a given user is not available or because a key for the
   *                              given user is available but it cannot be recognized as a valid
   *                              public key.
   */
  RSAPublicKey getKey(String username) throws KeyNotFoundException;
}
