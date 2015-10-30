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

package com.spotify.crtauth.signer;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;

import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.exceptions.CrtAuthException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.sshagentproxy.AgentProxies;
import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * AgentSigner is intended for command line tools where their invoker
 * also controls an ssh-agent process that can be contacted via a UNIX
 * referenced by the SSH_AUTH_SOCK environment variable.
 */
public class AgentSigner implements Signer, AutoCloseable {

  private final AgentProxy proxy;

  public AgentSigner() throws CrtAuthException {
    proxy = AgentProxies.newInstance();
  }

  @VisibleForTesting
  AgentSigner(final AgentProxy proxy) {
    this.proxy = proxy;
  }

  @Override
  public byte[] sign(final byte[] data, final Fingerprint fingerprint)
      throws IllegalArgumentException, KeyNotFoundException {
    try {
      final List<Identity> identities = proxy.list();
      for (final Identity id : identities) {
        if (!id.getPublicKey().getAlgorithm().equals("RSA")) {
          // TODO (dxia) Support other types of keys.
          continue;
        }
        if (fingerprint.matches((RSAPublicKey) id.getPublicKey())) {
          return proxy.sign(id, data);
        }
      }

      throw new KeyNotFoundException();
    } catch (IOException e) {
      throw new KeyNotFoundException(e);
    }
  }

  @Override
  public void close() throws Exception {
    proxy.close();
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .toString();
  }
}
