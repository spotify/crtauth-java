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

import com.google.common.io.BaseEncoding;
import com.spotify.crtauth.Fingerprint;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class SignerTest<T extends Signer> {
  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
  // RSA private key, PKCS#8, PEM
  private static final String PRIVATE_KEY_STRING =
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjKPW24a0Go7ET" +
      "iMP/j8DsnG+E6bB2DvCuX5hJLbBKE/oBMsZ3eB8MyROXmv/h0b0OzugEx+llxIo0" +
      "FpnsuJxMlF7xpEp7dHKHTUdxWIclmGjI6tzurX+sDerUuJk9gNj3SK67lcZI5tsr" +
      "XjDsy+ZpVQWcL/6trB9r69VDGm+GfnC8JIItLesAbJ1IcSq4/oU3e0mRjiaf5X/b" +
      "My1lRejcqEOARWhTVTw3D+EdPqAWZPh1IzREPnoNVp5MeSVU4hRdoZmJPwP9qF4f" +
      "2qbhsw0cDDPNFigU/UDw2kW9CUlGscrPs+0sj9wim4ZwMC9hmiFS/yfzHOaoTylF" +
      "kG6ia9W/AgMBAAECggEBAN9HJmWw4uJwyR+7QXOUN/waM59AF7ujKb0rp0LejrXx" +
      "dr3wy5UoU9S8W+6bYsHy51KD2xi/6tCl43YZdQhx2OeIut3nL3KzXdNSCVQGwSgZ" +
      "63z5JVnQ3XofX9/g5nbGi/xby6wEJpcHmwvAlHRcYsjL0izYHAtW8LeiYceIV3Co" +
      "Qq99W98mgpXJ2zSeyPvBV+f/P0kUJSesRuukk9jD3Yj/iAKgaimL3YAqAnM6ZRWz" +
      "gwOL8apS3ki6qKwORCLAMI8/YrbcESXcT7063tUzA3dihKhN7h6wWKJBYcMxRDXb" +
      "hXiJiEjHnIPVR/bMVl2qe7ol+hhQrrKFxUQTtbw9pOkCgYEA/hJBNBoUMnVktZOx" +
      "yFVLeyu70+NLzsGaQ5GgSlupXPmkAsF8MZjQOSFwZqIKeh2LsPQQLNIAy9Lsj3eR" +
      "UNW1Xzvrpn02bgkpnw9ZiEl1nmYm4qMuE38tmbuBI1+hr5m3YJm0Me+/ZZ4iXClI" +
      "VMv5cy8WocLj9cEoseQviE5KYSMCgYEA5OJoUBp1gP/yhDho5sLEQqjfG7zIZZh6" +
      "ouMgle01r/rrrEu965MNeILghzSVnreKNi1GyHSinM2ms4IBh6Q3SxfEit9u2fXT" +
      "GSzYZACOkK7/LSevyhulMETZ4h8D3E0UgOsyxH/9Mb9uEwAU+aZqNaabHJFASP39" +
      "1wKJXGAsuLUCgYBXeamBaskxZkG6UpOPSe6nBbOxjDx5fybBxM3PTCfPnxPc7wj3" +
      "eomWYfD1JS0+RhXmYuF+zP8BLinMa3pYvnunwlWsCMhIslbmML6+sawRUVJqDYy7" +
      "obntiCU6LJ7aeq4sUD8+QjE/p2ZlHMGOkHveMIQ2RYd/AXYlaU8EOxBYyQKBgF+Y" +
      "YFD0fBdAzx2CIe4fcrEUrvp6wogMQ0w86KM1y7KQblYr3ErDxGCM6RIPWF5N8h/m" +
      "kSWv8Srkibd3mQP6Bk4Kwz/tSfMmxOBC5q39vY2YSWOmq7kSCtA6MXZL1eTxHJsr" +
      "oKyJeEqK1YKCCkCqzLlTuH0Z/Wt/CcH/gTdfw83xAoGAOiB9c+3WekYwYC3Wr5Uq" +
      "tUZxE4Wp2UV7KuBDPpk45hJsLjKWyQcoz3Lsh2Hem9nMquSMovh6cu8HmABaaQLv" +
      "Y2ftflaxHyHvPUaiObhKwPz2tR42LycbjxQppIisXOJNRlzYpnx7FJqCZMY3f9dI" +
      "2BegNGjTK+tfd5X4JH1S3RY=";
  // RSA public key, X.509, PEM
  private static final String PUBLIC_KEY_STRING =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4yj1tuGtBqOxE4jD/4/A" +
      "7JxvhOmwdg7wrl+YSS2wShP6ATLGd3gfDMkTl5r/4dG9Ds7oBMfpZcSKNBaZ7Lic" +
      "TJRe8aRKe3Ryh01HcViHJZhoyOrc7q1/rA3q1LiZPYDY90iuu5XGSObbK14w7Mvm" +
      "aVUFnC/+rawfa+vVQxpvhn5wvCSCLS3rAGydSHEquP6FN3tJkY4mn+V/2zMtZUXo" +
      "3KhDgEVoU1U8Nw/hHT6gFmT4dSM0RD56DVaeTHklVOIUXaGZiT8D/aheH9qm4bMN" +
      "HAwzzRYoFP1A8NpFvQlJRrHKz7PtLI/cIpuGcDAvYZohUv8n8xzmqE8pRZBuomvV" +
      "vwIDAQAB";
  private T instance;
  private RSAPublicKey publicKey;

  protected abstract T getInstance(KeyPair keyPair) throws Exception;

  @Before
  public void setup() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    BaseEncoding encoding = BaseEncoding.base64();
    byte[] privateKeyBytes = encoding.decode(PRIVATE_KEY_STRING);
    KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
    byte[] publicKeyBytes = encoding.decode(PUBLIC_KEY_STRING);
    KeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    instance = getInstance(new KeyPair(publicKey, privateKey));
  }

  @Test
  public void testSign() throws Exception {
    byte [] serialized = {0, 127, 64};
    byte[] signature = instance.sign(serialized, new Fingerprint(publicKey));
    Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
    signer.initVerify(publicKey);
    signer.verify(signature);
  }

}
