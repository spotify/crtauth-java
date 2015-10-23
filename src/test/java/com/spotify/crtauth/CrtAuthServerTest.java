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

import com.spotify.crtauth.exceptions.ProtocolVersionException;
import com.spotify.crtauth.exceptions.TokenExpiredException;
import com.spotify.crtauth.keyprovider.InMemoryKeyProvider;
import com.spotify.crtauth.keyprovider.KeyProvider;
import com.spotify.crtauth.protocol.CrtAuthCodec;
import com.spotify.crtauth.protocol.Token;
import com.spotify.crtauth.signer.Signer;
import com.spotify.crtauth.signer.SingleKeySigner;
import com.spotify.crtauth.utils.ASCIICodec;
import com.spotify.crtauth.utils.TraditionalKeyParser;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static com.spotify.crtauth.utils.ASCIICodec.decode;
import static com.spotify.crtauth.utils.ASCIICodec.encode;

@SuppressWarnings("SpellCheckingInspection")
public class CrtAuthServerTest {
  private static final String NOA_PUBLIC_KEY =
      "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEArt7xdaxlbzzGlgLhqpLuE5x9d+so0M" +
      "JiqQSmiUJojuK+v1cxnYCnQQPF0BkAhw2hiFiDvLLVogIu8m2wCV9XAGxrz38NLHVq" +
      "ke+EAduJAfiiD1iwvSLbFBOMVRYfzUoiuPIudwZqmLuCpln1RUE6O/ujmYNyoPS4fq" +
      "a1svaiZ4C77tLMi2ztMIX97SN2o0EntrhOonJ1nk+7JLYvkhsT8rX20bg6Mlu909iO" +
      "vtTbElnypKzmjFZyBvzZhocRo4yfrekP3s2QyKSIB5ARGenoSoQa43cD93tqbLGK4o" +
      "JSkkfxc9HFPo0t+deDorZmelNNFvEn5KeqP0HJvw/jm2U1PQ== noa@vader.local";
  private static final String SERVER_NAME = "server_name";
  private static final String PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDK0wNhgGlFZfBo" +
      "RBS+M8wGoyOOVunYYjeaoRXKFKfhx288ZIo87WMfN6i5KnUTH3A/mYlVnK4bhchS6dUFisaXcURvFgY46pUSGuLTZ" +
      "xTe9anIIR/iT+V+8MRDHXffRGOCLEQUl0leYTht0dc7rxaW42d83yC7uuCISbgWqOANvMkZYqZjaejOOGVpkApxLG" +
      "G8K8RvNBBM8TYqE3DQHSyRVU6S9HWLbWF+i8W2h4CLX2Quodf0c1dcqlftClHjdIyed/zQKhAo+FDcJrN+2ZDJ0mk" +
      "YLVlJDZuLk/K/vSOwD3wXhby3cdHCsxnRfy2Ylnt31VF0aVtlhW4IJ+5mMzmz noa@date.office.spotify.net";
  private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEogIBAAKCAQEAytMDYYBpRWXwaEQUvjPMBqMjjlbp2GI3mqEVyhSn4cdvPGSK\n" +
      "PO1jHzeouSp1Ex9wP5mJVZyuG4XIUunVBYrGl3FEbxYGOOqVEhri02cU3vWpyCEf\n" +
      "4k/lfvDEQx1330RjgixEFJdJXmE4bdHXO68WluNnfN8gu7rgiEm4FqjgDbzJGWKm\n" +
      "Y2nozjhlaZAKcSxhvCvEbzQQTPE2KhNw0B0skVVOkvR1i21hfovFtoeAi19kLqHX\n" +
      "9HNXXKpX7QpR43SMnnf80CoQKPhQ3CazftmQydJpGC1ZSQ2bi5Pyv70jsA98F4W8\n" +
      "t3HRwrMZ0X8tmJZ7d9VRdGlbZYVuCCfuZjM5swIDAQABAoIBADtnoHbfQHYGDGrN\n" +
      "ffHTg+9xuslG5YjuA3EzuwkMEbvMSOU8YUzFDqInEDDjoZSvQZYvJw0/LbN79Jds\n" +
      "S2srIU1b7HpIzhu/gVfjLgpTB8bh1w95vDfxxLrwU9uAdwqaojaPNoV9ZgzRltB7\n" +
      "hHnDp28cPcRSKekyK+9fAB8K6Uy8N00hojBDwtwXM8C4PpQKod38Vd0Adp9dEdX6\n" +
      "Ro9suYb+d+qFalYbKIbjKWkll+ZiiGJjF1HSQCTwlzS2haPXUlbk57HnN+8ar+a3\n" +
      "ITTc2gbNuTqBRD1V/gCaD9F0npVI3mQ34eUADNVVGS0xw0pN4j++Da8KXP+pyn/G\n" +
      "DU/n8SECgYEA/KN4BTrg/LB7cGrzkMQmW26NA++htjiWHK3WTsQBKBDFyReJBn67\n" +
      "o9kMTHBP35352RfuJ3xEEJ0/ddqGEY/SzNk3HMTlxBbR5Xq8ye102dxfEO3eijJ/\n" +
      "F4VRSf9sFgdRoLvE62qLudytK4Ku9nnKoIqrMxFweTpwxzf2jjIKDbECgYEAzYXe\n" +
      "QxT1A/bfs5Qd6xoCVOAb4T/ALqFo95iJu4EtFt7nvt7avqL+Vsdxu5uBkTeEUHzh\n" +
      "1q47LFoFdGm+MesIIiPSSrbfZJ6ht9kw8EbF8Py85X4LBXey67JlzzUq+ewFEP91\n" +
      "do7uGQAY+BRwXtzzPqaVBVa94YOxdq/AGutrIqMCgYBr+cnQImwKU7tOPse+tbbX\n" +
      "GRa3+fEZmnG97CZOH8OGxjRiT+bGmd/ElX2GJfJdVn10ZZ/pzFii6TI4Qp9OXjPw\n" +
      "TV4as6Sn/EDVXXHWs+BfRKp059VXJ2HeQaKOh9ZAS/x9QANXwn/ZfhGdKQtyWHdb\n" +
      "yiiFeQyjI3EUFD0SZRya4QKBgA1QvQOvmeg12Gx0DjQrLTd+hY/kZ3kd8AUKlvHU\n" +
      "/qzaqD0PhzCOstfAeDflbVGRPTtRu/gCtca71lqidzYYuiAsHfXFP1fvhx64LZmD\n" +
      "nFNurHZZ4jDqfmcS2dHA6hXjGrjtNBkITZjFDtkTyev7eK74b/M2mXrA44CDBnk4\n" +
      "A2rtAoGAMv92fqI+B5taxlZhTLAIaGVFbzoASHTRl3eQJbc4zc38U3Zbiy4deMEH\n" +
      "3QTXq7nxWpE4YwHbgXAeJUGfUpE+nEZGMolj1Q0ueKuSstQg5p1nwhQIxej8EJW+\n" +
      "7siqmOTZDKzieik7KVzaJ/U02Q186smezKIuAOYtT8VCf9UksJ4=\n" +
      "-----END RSA PRIVATE KEY-----";
  private InMemoryKeyProvider keyProvider;
  private CrtAuthServer crtAuthServer;
  private CrtAuthClient crtAuthClient;

  @Before
  public void setup() throws Exception {
    keyProvider = new InMemoryKeyProvider();
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec noaPublicKeySpec = TraditionalKeyParser.parsePemPublicKey(NOA_PUBLIC_KEY);
    RSAPublicKey noaPublicKey = (RSAPublicKey) keyFactory.generatePublic(noaPublicKeySpec);
    keyProvider.putKey("noa", noaPublicKey);
    RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_KEY);
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    keyProvider.putKey("test", publicKey);
    crtAuthServer = new CrtAuthServer.Builder()
        .setServerName(SERVER_NAME)
        .setSecret("server_secret".getBytes())
        .setKeyProvider(keyProvider)
        .build();
    RSAPrivateKeySpec privateKeySpec = TraditionalKeyParser.parsePemPrivateKey(PRIVATE_KEY);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
    Signer signer = new SingleKeySigner(privateKey);
    crtAuthClient = new CrtAuthClient(signer, SERVER_NAME);
  }

  @Test
  public void testCreateChallenge() throws Exception {
    byte[] serverSecret = "spotify".getBytes();
    CrtAuthServer crtAuthServer = new CrtAuthServer.Builder()
        .setServerName("server_name")
        .setSecret(serverSecret)
        .setKeyProvider(keyProvider)
        .build();
    String challenge = crtAuthServer.createChallenge(CrtAuthClient.createRequest("noa"));
    Fingerprint expectedFingerprint = new Fingerprint(decode("-6Hqb9N5"));
    Assert.assertTrue(extractFingerprint(challenge).equals(expectedFingerprint));
  }

  @Test
  public void testCreateChallengeUnknownUser() throws Exception {
    byte[] serverSecret = "spotify".getBytes();
    CrtAuthServer crtAuthServer = new CrtAuthServer.Builder()
        .setServerName("server_name")
        .setSecret(serverSecret)
        .setKeyProvider(keyProvider)
        .build();
    String encodedChallenge = crtAuthServer.createChallenge(CrtAuthClient.createRequest("another"));
    // just make sure that we have a parsable challenge
    CrtAuthCodec.deserializeChallenge(ASCIICodec.decode(encodedChallenge));
  }

  @Test
  public void testCreateChallengeMultipleKeyProviders() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    InMemoryKeyProvider keyProvider1 = new InMemoryKeyProvider();
    RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_KEY);
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    keyProvider1.putKey("test", publicKey);

    InMemoryKeyProvider keyProvider2 = new InMemoryKeyProvider();
    RSAPublicKeySpec noaPublicKeySpec = TraditionalKeyParser.parsePemPublicKey(NOA_PUBLIC_KEY);
    RSAPublicKey noaPublicKey = (RSAPublicKey) keyFactory.generatePublic(noaPublicKeySpec);
    keyProvider2.putKey("noa", noaPublicKey);

    byte[] serverSecret = "spotify".getBytes();
    CrtAuthServer crtAuthServer = new CrtAuthServer.Builder()
        .setServerName("server_name")
        .setSecret(serverSecret)
        .addKeyProvider(keyProvider1)
        .addKeyProvider(keyProvider2)
        .build();
    String challenge = crtAuthServer.createChallenge(CrtAuthClient.createRequest("noa"));
    Fingerprint expectedFingerprint = new Fingerprint(decode("-6Hqb9N5"));
    Assert.assertTrue(extractFingerprint(challenge).equals(expectedFingerprint));
  }

  private Fingerprint extractFingerprint(String challenge) throws ProtocolVersionException {
    return CrtAuthCodec.deserializeChallenge(decode(challenge)).getFingerprint();
  }

  @Test(expected = IllegalArgumentException.class)
  public void testMitm() throws Exception {
    CrtAuthServer otherOuthServer = new CrtAuthServer.Builder()
        .setServerName("another_server")
        .setSecret("server_secret".getBytes())
        .setKeyProvider(keyProvider)
        .build();
    String verifiableChallenge = crtAuthServer.createChallenge(CrtAuthClient.createRequest("test"));
    String response = crtAuthClient.createResponse(verifiableChallenge);
    otherOuthServer.createToken(response);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testWrongSecret() throws Exception {
    CrtAuthServer otherServer = new CrtAuthServer.Builder()
        .setServerName("SERVER_NAME")
        .setSecret("another_secret".getBytes())
        .setKeyProvider(keyProvider)
        .build();
    String verifiableChallenge = crtAuthServer.createChallenge(CrtAuthClient.createRequest("test"));
    String response = crtAuthClient.createResponse(verifiableChallenge);
    otherServer.validateToken(crtAuthServer.createToken(response));
  }

  @Test
  public void testGoodToken() throws Exception {
    int nowSeconds = (int) (System.currentTimeMillis() / 1000);
    Token t = new Token(nowSeconds, nowSeconds + 10, "test");
    String ts = encode(CrtAuthCodec.serialize(t, "server_secret".getBytes()));
    crtAuthServer.validateToken(ts);
  }

  @Test(expected = TokenExpiredException.class)
  public void testExpiredToken() throws Exception {
    int nowSeconds = (int) (System.currentTimeMillis() / 1000);
    Token t = new Token(nowSeconds - 1000, nowSeconds - 950, "test");
    String ts = encode(CrtAuthCodec.serialize(t, "server_secret".getBytes()));
    crtAuthServer.validateToken(ts);
  }

  @Test(expected = TokenExpiredException.class)
  public void testFutureToken() throws Exception {
    int nowSeconds = (int) (System.currentTimeMillis() / 1000);
    Token t = new Token(nowSeconds + 1000, nowSeconds + 1050, "test");
    String ts = encode(CrtAuthCodec.serialize(t, "server_secret".getBytes()));
    crtAuthServer.validateToken(ts);
  }

  @Test(expected = TokenExpiredException.class)
  public void testOverlyLongTokenValidity() throws Exception {
    int nowSeconds = (int) (System.currentTimeMillis() / 1000);
    Token t = new Token(nowSeconds, nowSeconds + 10000, "test");
    String ts = encode(CrtAuthCodec.serialize(t, "server_secret".getBytes()));
    crtAuthServer.validateToken(ts);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testBuilderFailsOnOverlyLongTokenValidity() throws Exception {
    new CrtAuthServer.Builder()
        .setServerName(SERVER_NAME)
        .setSecret("server_secret".getBytes())
        .setKeyProvider(keyProvider)
        .setTokenLifetimeSeconds(1000)
        .build();
  }

  @Test(expected = IllegalArgumentException.class)
  public void testBuliderFailsOnNoKeyProviders() throws Exception {
    new CrtAuthServer.Builder()
        .setServerName(SERVER_NAME)
        .setSecret("server_secret".getBytes())
        .build();
  }
}
