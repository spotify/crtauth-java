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

package com.spotify.crtauth;

import com.google.common.io.BaseEncoding;
import com.spotify.crtauth.utils.TraditionalKeyParser;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import static org.junit.Assert.assertEquals;

public class FingerprintTest {
  private static final String PUBLIC_PEM_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjKPW24a0" +
      "Go7ETiMP/j8DsnG+E6bB2DvCuX5hJLbBKE/oBMsZ3eB8MyROXmv/h0b0OzugEx+llxIo0FpnsuJxMlF7xpEp7dHK" +
      "HTUdxWIclmGjI6tzurX+sDerUuJk9gNj3SK67lcZI5tsrXjDsy+ZpVQWcL/6trB9r69VDGm+GfnC8JIItLesAbJ1" +
      "IcSq4/oU3e0mRjiaf5X/bMy1lRejcqEOARWhTVTw3D+EdPqAWZPh1IzREPnoNVp5MeSVU4hRdoZmJPwP9qF4f2qb" +
      "hsw0cDDPNFigU/UDw2kW9CUlGscrPs+0sj9wim4ZwMC9hmiFS/yfzHOaoTylFkG6ia9W/ test@spotify.net";

  @Test
  public void testFingerprint() throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final String expectedEncodedFingerprint = "c/XR6bib";
    BaseEncoding encoding = BaseEncoding.base64();

    RSAPublicKeySpec keySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_PEM_KEY);
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
    Fingerprint actual = new Fingerprint(publicKey);
    Fingerprint expected = new Fingerprint(encoding.decode(expectedEncodedFingerprint));
    assertEquals(actual, expected);
  }
}
