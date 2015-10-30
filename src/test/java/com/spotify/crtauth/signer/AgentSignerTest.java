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

import com.google.common.collect.ImmutableList;

import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class AgentSignerTest extends SignerTest<AgentSigner> {

  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

  private static final AgentProxy proxy = mock(AgentProxy.class);

  @Override
  protected AgentSigner getInstance(final KeyPair keyPair) throws Exception {
    final Identity id = new TestIdentity(keyPair);
    when(proxy.list()).thenReturn(ImmutableList.of(id));
    when(proxy.sign(eq(id), any(byte[].class))).thenAnswer(new Answer<byte[]>() {
      @Override
      public byte[] answer(InvocationOnMock invocation) throws Throwable {
        final Object[] args = invocation.getArguments();
        final byte[] data = (byte[]) args[1];
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
      }
    });
    return new AgentSigner(proxy);
  }

  private static class TestIdentity implements Identity {

    private final PublicKey publicKey;

    TestIdentity(final KeyPair keyPair) {
      this.publicKey = keyPair.getPublic();
    }

    @Override
    public String getKeyFormat() {
      return publicKey.getFormat();
    }

    @Override
    public PublicKey getPublicKey() {
      return publicKey;
    }

    @Override
    public String getComment() {
      return null;
    }

    @Override
    public byte[] getKeyBlob() {
      return publicKey.getEncoded();
    }
  }
}
