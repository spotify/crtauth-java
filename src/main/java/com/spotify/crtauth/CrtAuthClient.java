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

import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.SignerException;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.protocol.Response;
import com.spotify.crtauth.protocol.VerifiableMessage;
import com.spotify.crtauth.signer.Signer;

/**
 * This class implements the client-side methods used for authentication. Note that there is no
 * middleware layer that takes care of communication. In order to be able to authenticate a
 * remote client, a middleware layer wrapping the {@CrtAuthClient} class has to be implemented
 * separately.
 */
public class CrtAuthClient {
  private final Signer signer;
  private final String serverName;

  public CrtAuthClient(Signer signer, String serverName) {
    this.signer = signer;
    this.serverName = serverName;
  }

  /**
   * Return a response to the given challenge.
   * @param verifiableChallenge A challenge wrapped in a verifiable message.
   * @return The response to the challenge.
   * @throws InvalidInputException If anything is wrong with the input challenge,
   *    for example if the content of the challenge is compromised and suggests a potential MITM
   *    attack.
   * @throws SignerException If a valid signature for the input challenge cannot be produced.
   */
  public Response createResponse(VerifiableMessage<Challenge> verifiableChallenge)
      throws InvalidInputException, SignerException {
    Challenge challenge = verifiableChallenge.getPayload();
    if (!challenge.getServerName().equals(serverName)) {
      throw new InvalidInputException("Possible MITM attack.");
    }
    byte[] signature = signer.sign(challenge);
    Response response = new Response.Builder()
        .setSignature(signature)
        .setVerifiableChallenge(verifiableChallenge)
        .build();
    return response;
  }
}
