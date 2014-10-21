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

package com.spotify.crtauth.protocol;

import com.spotify.crtauth.ASCIICodec;
import com.spotify.crtauth.CrtAuthClientTest;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.signer.Signer;
import com.spotify.crtauth.signer.SingleKeySigner;
import org.junit.Assert;
import org.junit.Test;

public class ResponseTest {

  private static final byte[] SERIALIZED_RESPONSE = ASCIICodec.decode(
      "AXLEaAFjxBR1WEZP0tt__n1_k5EgdmiJRzYfws5RXYiuzlFdidrEBkyaBxLLHrJzZXJ2ZXIuZXhhbXBsZS5jb22o" +
      "dXNlcm5hbWXEIPct6Mgb-MVH6TxwvWXB6I_nNYYx7To_U0p_41b7_BCyxQEAPymreRi3DDVCz5rUdCqLCdCP89pY" +
      "pnrBJ-p9yWColikZcoV6aY7xbEqRpY40fcgGcSmXVPZBCxCQ67YWAlFLuBs72YOBTd-lkABFe_-tnu_58k_Ll-Cd" +
      "S6UKU_NyzB0beKMQy3x4Bq4s35Jxtvsl1zjueyCOzUbS2Y-2evq9_cQBUHCbbbv-PmqU4fqvZ3KkTmQpQXHpE0rh" +
      "WFk_XdSiuNofT5lK38MPqbzfTcSwO0QKD-IJUhOrVo8nMcrbe-hNAIc9mM_qV1-qcUQMEMwVqRv7G4DIH71k0CEr" +
      "xfP_x024iQAf4fxRzGLBoq9ENWrMtLcieQ3AtoyoNDbWWSHVhg=="
  );

  @Test
  public void testSerializeResponse() throws Exception {
    Signer signer = new SingleKeySigner(CrtAuthClientTest.getPrivateKey());
    byte[] signature = signer.sign(
        ChallengeTest.ENCODED_CHALLENGE,
        getFingerprint(ChallengeTest.ENCODED_CHALLENGE)
    );
    Response resp = new Response(ChallengeTest.ENCODED_CHALLENGE, signature);
    Assert.assertArrayEquals(SERIALIZED_RESPONSE, resp.serialize());
  }

  @Test
  public void testDeserializeResponse() throws Exception {
    Response r = Response.deserialize(SERIALIZED_RESPONSE);
    Challenge c = Challenge.deserialize(r.getPayload());

    Signer signer = new SingleKeySigner(CrtAuthClientTest.getPrivateKey());
    byte[] signature = signer.sign(r.getPayload(), c.getFingerprint());
    Assert.assertArrayEquals(signature, r.getSignature());
    Assert.assertEquals(c, ChallengeTest.getTestChallenge());
  }

  private byte[] getFingerprint(byte[] challenge) throws DeserializationException {
    return Challenge.deserialize(challenge).getFingerprint();
  }
}
