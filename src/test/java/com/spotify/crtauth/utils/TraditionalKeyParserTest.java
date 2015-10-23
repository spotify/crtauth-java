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

package com.spotify.crtauth.utils;

import com.google.common.io.BaseEncoding;

import org.junit.Test;

import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPrivateKeyImpl;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

@SuppressWarnings("restriction")
public class TraditionalKeyParserTest {
  private static final String X509_PEM_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
      "4yj1tuGtBqOxE4jD/4/A7JxvhOmwdg7wrl+YSS2wShP6ATLGd3gfDMkTl5r/4dG9Ds7oBMfpZcSKNBaZ7LicTJRe8a" +
      "RKe3Ryh01HcViHJZhoyOrc7q1/rA3q1LiZPYDY90iuu5XGSObbK14w7MvmaVUFnC/+rawfa+vVQxpvhn5wvCSCLS3r" +
      "AGydSHEquP6FN3tJkY4mn+V/2zMtZUXo3KhDgEVoU1U8Nw/hHT6gFmT4dSM0RD56DVaeTHklVOIUXaGZiT8D/aheH9" +
      "qm4bMNHAwzzRYoFP1A8NpFvQlJRrHKz7PtLI/cIpuGcDAvYZohUv8n8xzmqE8pRZBuomvVvwIDAQAB";
  private static final String PKCS1_PEM_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjKPW" +
      "24a0Go7ETiMP/j8DsnG+E6bB2DvCuX5hJLbBKE/oBMsZ3eB8MyROXmv/h0b0OzugEx+llxIo0FpnsuJxMlF7xpEp7d" +
      "HKHTUdxWIclmGjI6tzurX+sDerUuJk9gNj3SK67lcZI5tsrXjDsy+ZpVQWcL/6trB9r69VDGm+GfnC8JIItLesAbJ1" +
      "IcSq4/oU3e0mRjiaf5X/bMy1lRejcqEOARWhTVTw3D+EdPqAWZPh1IzREPnoNVp5MeSVU4hRdoZmJPwP9qF4f2qbhs" +
      "w0cDDPNFigU/UDw2kW9CUlGscrPs+0sj9wim4ZwMC9hmiFS/yfzHOaoTylFkG6ia9W/ test@spotify.net";
  private static final String PCKS1_PEM_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEowIBAAKCAQEA4yj1tuGtBqOxE4jD/4/A7JxvhOmwdg7wrl+YSS2wShP6ATLG\n" +
      "d3gfDMkTl5r/4dG9Ds7oBMfpZcSKNBaZ7LicTJRe8aRKe3Ryh01HcViHJZhoyOrc\n" +
      "7q1/rA3q1LiZPYDY90iuu5XGSObbK14w7MvmaVUFnC/+rawfa+vVQxpvhn5wvCSC\n" +
      "LS3rAGydSHEquP6FN3tJkY4mn+V/2zMtZUXo3KhDgEVoU1U8Nw/hHT6gFmT4dSM0\n" +
      "RD56DVaeTHklVOIUXaGZiT8D/aheH9qm4bMNHAwzzRYoFP1A8NpFvQlJRrHKz7Pt\n" +
      "LI/cIpuGcDAvYZohUv8n8xzmqE8pRZBuomvVvwIDAQABAoIBAQDfRyZlsOLicMkf\n" +
      "u0FzlDf8GjOfQBe7oym9K6dC3o618Xa98MuVKFPUvFvum2LB8udSg9sYv+rQpeN2\n" +
      "GXUIcdjniLrd5y9ys13TUglUBsEoGet8+SVZ0N16H1/f4OZ2xov8W8usBCaXB5sL\n" +
      "wJR0XGLIy9Is2BwLVvC3omHHiFdwqEKvfVvfJoKVyds0nsj7wVfn/z9JFCUnrEbr\n" +
      "pJPYw92I/4gCoGopi92AKgJzOmUVs4MDi/GqUt5IuqisDkQiwDCPP2K23BEl3E+9\n" +
      "Ot7VMwN3YoSoTe4esFiiQWHDMUQ124V4iYhIx5yD1Uf2zFZdqnu6JfoYUK6yhcVE\n" +
      "E7W8PaTpAoGBAP4SQTQaFDJ1ZLWTschVS3sru9PjS87BmkORoEpbqVz5pALBfDGY\n" +
      "0DkhcGaiCnodi7D0ECzSAMvS7I93kVDVtV8766Z9Nm4JKZ8PWYhJdZ5mJuKjLhN/\n" +
      "LZm7gSNfoa+Zt2CZtDHvv2WeIlwpSFTL+XMvFqHC4/XBKLHkL4hOSmEjAoGBAOTi\n" +
      "aFAadYD/8oQ4aObCxEKo3xu8yGWYeqLjIJXtNa/666xLveuTDXiC4Ic0lZ63ijYt\n" +
      "Rsh0opzNprOCAYekN0sXxIrfbtn10xks2GQAjpCu/y0nr8obpTBE2eIfA9xNFIDr\n" +
      "MsR//TG/bhMAFPmmajWmmxyRQEj9/dcCiVxgLLi1AoGAV3mpgWrJMWZBulKTj0nu\n" +
      "pwWzsYw8eX8mwcTNz0wnz58T3O8I93qJlmHw9SUtPkYV5mLhfsz/AS4pzGt6WL57\n" +
      "p8JVrAjISLJW5jC+vrGsEVFSag2Mu6G57YglOiye2nquLFA/PkIxP6dmZRzBjpB7\n" +
      "3jCENkWHfwF2JWlPBDsQWMkCgYBfmGBQ9HwXQM8dgiHuH3KxFK76esKIDENMPOij\n" +
      "NcuykG5WK9xKw8RgjOkSD1heTfIf5pElr/Eq5Im3d5kD+gZOCsM/7UnzJsTgQuat\n" +
      "/b2NmEljpqu5EgrQOjF2S9Xk8RybK6CsiXhKitWCggpAqsy5U7h9Gf1rfwnB/4E3\n" +
      "X8PN8QKBgDogfXPt1npGMGAt1q+VKrVGcROFqdlFeyrgQz6ZOOYSbC4ylskHKM9y\n" +
      "7Idh3pvZzKrkjKL4enLvB5gAWmkC72Nn7X5WsR8h7z1Gojm4SsD89rUeNi8nG48U\n" +
      "KaSIrFziTUZc2KZ8exSagmTGN3/XSNgXoDRo0yvrX3eV+CR9Ut0W\n" +
      "-----END RSA PRIVATE KEY-----";
  private static final String PCKS8_PEM_PRIVATE_KEY =
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

  @Test
  public void testDecodePublicKey() throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    BaseEncoding encoding = BaseEncoding.base64();
    byte[] expectedKeyBytes = encoding.decode(X509_PEM_PUBLIC_KEY);
    KeySpec publicKeySpec = new X509EncodedKeySpec(expectedKeyBytes);
    PublicKey expected = keyFactory.generatePublic(publicKeySpec);
    RSAPublicKeySpec keySpec = TraditionalKeyParser.parsePemPublicKey(PKCS1_PEM_PUBLIC_KEY);
    PublicKey actual = keyFactory.generatePublic(keySpec);
    assertEquals(expected, actual);
  }

  @Test
  public void decodePrivateKey() throws Exception {
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    BaseEncoding encoding = BaseEncoding.base64();
    byte[] expectedKeyBytes = encoding.decode(PCKS8_PEM_PRIVATE_KEY);
    KeySpec expectedKeySpec = new PKCS8EncodedKeySpec(expectedKeyBytes);
    RSAPrivateCrtKeyImpl expected = (RSAPrivateCrtKeyImpl)
        keyFactory.generatePrivate(expectedKeySpec);
    KeySpec actualKeySpac = TraditionalKeyParser.parsePemPrivateKey(PCKS1_PEM_PRIVATE_KEY);
    RSAPrivateKeyImpl actual = (RSAPrivateKeyImpl) keyFactory.generatePrivate(actualKeySpac);
    assertEquals(actual.getModulus(), expected.getModulus());
    assertEquals(actual.getPrivateExponent(), expected.getPrivateExponent());
  }
}
