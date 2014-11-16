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

package com.spotify.crtauth;

import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.SignerException;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.protocol.CrtAuthCodec;
import com.spotify.crtauth.protocol.Response;
import com.spotify.crtauth.signer.Signer;

import static com.spotify.crtauth.ASCIICodec.decode;
import static com.spotify.crtauth.ASCIICodec.encode;

/**
 * This class creates a response String given a challenge from a server using the
 * Signer instance provided in the constructor. Additionally, this class verifies that the
 * serverName embedded in the challenge matches serverName, to prevent attacks when a client
 * is tricked to sign a challenge for an unrelated serverName by an attacker.
 */
public class CrtAuthClient {
  private final Signer signer;
  private final String serverName;

  /**
   * Construct an CrtAuthClient instance backed by the provided signer.
   *
   * @param signer a Signer instance to back the constructed instance.
   * @param serverName the name of the server this client gets requests from.
   */
  public CrtAuthClient(Signer signer, String serverName) {
    this.signer = signer;
    this.serverName = serverName;
  }

  /**
   * Generate a response String using the Signer of this instance, additionally verifying
   * that the embedded serverName matches the serverName of this instance.
   *
   * @param challenge A challenge String obtained from a server.
   * @return The response String to be returned to the server.
   * @throws InvalidInputException if there is something wrong with the challenge.
   * @throws SignerException If a valid signature for the input challenge cannot be produced.
   */
  public String createResponse(String challenge)
      throws InvalidInputException, SignerException, KeyNotFoundException {
    byte[] decodedChallenge = decode(challenge);
    Challenge deserializedChallenge;
    try {
      deserializedChallenge = CrtAuthCodec.deserializeChallenge(decodedChallenge);
    } catch (DeserializationException e) {
      throw new InvalidInputException(e);
    }
    if (!deserializedChallenge.getServerName().equals(serverName)) {
      throw new InvalidInputException("Invalid serverName in challenge. Possible MITM attack.");
    }
    byte[] signature = signer.sign(decodedChallenge, deserializedChallenge.getFingerprint());
    try {
      return encode(CrtAuthCodec.serialize(new Response(decodedChallenge, signature)));
    } catch (SerializationException e) {
      throw new InvalidInputException(e);
    }
  }
}
