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

import com.google.common.annotations.VisibleForTesting;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.exceptions.SignerException;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.utils.PublicKeys;
import org.apache.sshd.agent.SshAgent;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

public class AgentSigner implements Signer {
  private SshAgent sshAgent;

  public AgentSigner(SshAgent sshAgent) {
    this.sshAgent = sshAgent;
  }

  @VisibleForTesting
  PublicKey getKeyFromFingerprint(byte[] referenceFingerprint) throws IOException,
      NoSuchAlgorithmException{
    List<SshAgent.Pair<PublicKey, String>> identities = sshAgent.getIdentities();
    for (SshAgent.Pair<PublicKey, String> identity : identities) {
      RSAPublicKey publicKey = (RSAPublicKey) identity.getFirst();
      byte[] fingerprint = PublicKeys.generateFingerprint(publicKey);
      if (Arrays.equals(referenceFingerprint, fingerprint)) {
        return publicKey;
      }
    }
    return null;
  }

  @Override
  public byte[] sign(Challenge challenge) throws SignerException {
    PublicKey publicKey;
    try {
      publicKey = getKeyFromFingerprint(challenge.getFingerprint());
    } catch (IOException | NoSuchAlgorithmException exception) {
      throw new SignerException();
    }
    if (publicKey == null) {
      throw new SignerException("Key not found");
    }
    byte[] signed;
    try {
      signed = sshAgent.sign(publicKey, challenge.serialize());
    } catch (IOException | SerializationException e) {
      throw new SignerException();
    }
    return signed;
  }
}
