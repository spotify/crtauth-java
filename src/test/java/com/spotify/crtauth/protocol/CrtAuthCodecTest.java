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

package com.spotify.crtauth.protocol;

import com.google.common.primitives.UnsignedInteger;
import com.spotify.crtauth.CrtAuthClientTest;
import com.spotify.crtauth.Fingerprint;
import com.spotify.crtauth.signer.Signer;
import com.spotify.crtauth.signer.SingleKeySigner;
import com.spotify.crtauth.utils.ASCIICodec;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;

/**
 * Tests CrtAuthCodec
 */
public class CrtAuthCodecTest {

  // ENCODED_ data is encoded using the python implementation, to ensure binary compatibility
  private static final byte[] ENCODED_CHALLENGE =
      ASCIICodec.decode("AWPEFHVYRk_S23_-fX-TkSB2aIlHNh_CzlFdiK7OUV2J2sQGTJoHEssesnNlcnZlci5leG" +
          "FtcGxlLmNvbah1c2VybmFtZcQg9y3oyBv4xUfpPHC9ZcHoj-c1hjHtOj9TSn_jVvv8ELI=");

  private static final byte[] ENCODED_RESPONSE = ASCIICodec.decode(
      "AXLEaAFjxBR1WEZP0tt__n1_k5EgdmiJRzYfws5RXYiuzlFdidrEBkyaBxLLHrJzZXJ2ZXIuZXhhbXBsZS5jb22o" +
      "dXNlcm5hbWXEIPct6Mgb-MVH6TxwvWXB6I_nNYYx7To_U0p_41b7_BCyxQEAPymreRi3DDVCz5rUdCqLCdCP89pY" +
      "pnrBJ-p9yWColikZcoV6aY7xbEqRpY40fcgGcSmXVPZBCxCQ67YWAlFLuBs72YOBTd-lkABFe_-tnu_58k_Ll-Cd" +
      "S6UKU_NyzB0beKMQy3x4Bq4s35Jxtvsl1zjueyCOzUbS2Y-2evq9_cQBUHCbbbv-PmqU4fqvZ3KkTmQpQXHpE0rh" +
      "WFk_XdSiuNofT5lK38MPqbzfTcSwO0QKD-IJUhOrVo8nMcrbe-hNAIc9mM_qV1-qcUQMEMwVqRv7G4DIH71k0CEr" +
      "xfP_x024iQAf4fxRzGLBoq9ENWrMtLcieQ3AtoyoNDbWWSHVhg=="
  );

  private static final byte[] ENCODED_TOKEN = ASCIICodec.decode(
      "AXTOUV2Irs5RXYnao25vYcQgKVlUyZneScS57Xwk2syvL0GTQhV0FF9ciWQZYluN4m8="
  );

  private static final Challenge CHALLENGE = Challenge.newBuilder()
        .setUniqueData(ASCIICodec.decode("dVhGT9Lbf_59f5ORIHZoiUc2H8I="))
        .setFingerprint(new Fingerprint(ASCIICodec.decode("TJoHEsse")))
        .setValidFromTimestamp(UnsignedInteger.valueOf(1365084334).intValue())
        .setValidToTimestamp(UnsignedInteger.valueOf(1365084634).intValue())
        .setServerName("server.example.com")
        .setUserName("username")
        .build();


  static final Token TOKEN = new Token(1365084334, 1365084634, "noa");

  @Test
  public void testSerializeChallenge() throws Exception {

    byte[] bytes = CrtAuthCodec.serialize(CHALLENGE, "secret".getBytes());
    Assert.assertArrayEquals(ENCODED_CHALLENGE, bytes);
  }

  @Test
  public void testDeserializeChallenge() throws Exception {
    Challenge challenge = CrtAuthCodec.deserializeChallengeAuthenticated(
        ENCODED_CHALLENGE, "secret".getBytes());

    assertEquals(CHALLENGE, challenge);
  }

  @Test
  public void testSerializeResponse() throws Exception {
    Signer signer = new SingleKeySigner(CrtAuthClientTest.getPrivateKey());
    byte[] signature = signer.sign(
        CrtAuthCodecTest.ENCODED_CHALLENGE,
        CrtAuthCodec.deserializeChallenge(CrtAuthCodecTest.ENCODED_CHALLENGE).getFingerprint()
    );
    Response resp = new Response(CrtAuthCodecTest.ENCODED_CHALLENGE, signature);
    Assert.assertArrayEquals(ENCODED_RESPONSE, CrtAuthCodec.serialize(resp));
  }

  @Test
  public void testDeserializeResponse() throws Exception {
    Response r = CrtAuthCodec.deserializeResponse(CrtAuthCodecTest.ENCODED_RESPONSE);
    Challenge c = CrtAuthCodec.deserializeChallenge(r.getPayload());

    Signer signer = new SingleKeySigner(CrtAuthClientTest.getPrivateKey());
    byte[] signature = signer.sign(r.getPayload(), c.getFingerprint());
    Assert.assertArrayEquals(signature, r.getSignature());
    assertEquals(c, CHALLENGE);
  }

  @Test
  public void testSerializeToken() throws Exception {
    Assert.assertArrayEquals(CrtAuthCodec.serialize(TOKEN, "gurkburk".getBytes()), ENCODED_TOKEN);
  }

  @Test
  public void testDeserializeToken() throws Exception {
    Token token = CrtAuthCodec.deserializeTokenAuthenticated(ENCODED_TOKEN, "gurkburk".getBytes());
    assertEquals(TOKEN, token);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDeserializeAuthenticatedTokenCorrupt() throws Exception {
    byte[] mine = Arrays.copyOf(
        CrtAuthCodecTest.ENCODED_TOKEN, CrtAuthCodecTest.ENCODED_TOKEN.length);
    mine[mine.length - 4] = 't';
    CrtAuthCodec.deserializeTokenAuthenticated(mine, "gurkburk".getBytes());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDeserializeAuthenticatedChallengeCorrupt() throws Exception {
    byte[] mine = Arrays.copyOf(
        CrtAuthCodecTest.ENCODED_CHALLENGE, CrtAuthCodecTest.ENCODED_CHALLENGE.length);
    mine[mine.length - 4] = 't';
    CrtAuthCodec.deserializeChallengeAuthenticated(mine, "secret".getBytes());
  }


  @Test
  public void testDeserializeRequest() throws Exception {
    assertEquals("noa", CrtAuthCodec.deserializeRequest("AXGjbm9h"));
  }

}
