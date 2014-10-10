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

import com.spotify.crtauth.digest.DigestAlgorithm;
import com.spotify.crtauth.digest.MessageHashDigestAlgorithm;
import com.spotify.crtauth.exceptions.DeserializationException;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class VerifiableMessageTest extends XdrSerializableTest<VerifiableMessage<Challenge>> {
  @Override
  protected VerifiableMessage<Challenge> getInstance() throws Exception {
    return getVerifiableMessageChallenge();
  }

  @Override
  protected MessageDeserializer<VerifiableMessage<Challenge>> getDeserializer() {
    return new MessageDeserializer<VerifiableMessage<Challenge>>() {
      @Override
      public VerifiableMessage<Challenge> deserialize(byte[] data)
          throws DeserializationException {
        return VerifiableMessage.deserialize(data, Challenge.deserializer());
      }
    };
  }

  @Test
  public void testDeserializePayloadChallenge() throws Exception {
    VerifiableMessage<Challenge> verifiableMessage = getVerifiableMessageChallenge();
    byte[] data = verifiableMessage.serialize();
    VerifiableMessage<Challenge> deserialized = VerifiableMessage.deserialize(data, Challenge.deserializer());
    assertEquals(deserialized.getPayload(), getVerifiableMessageChallenge().getPayload());
  }

  @Test
  public void testDeserializePayloadToken() throws Exception {
    VerifiableMessage<Token> verifiableMessage = getVerifiableMessageToken();
    byte[] data = verifiableMessage.serialize();
    VerifiableMessage<Token> deserialized = VerifiableMessage.deserialize(data, Token.deserializer());
    assertEquals(deserialized.getPayload(), getVerifiableMessageToken().getPayload());
  }

  @Test
  public void testVerifyMessage() throws Exception {
    DigestAlgorithm digestAlgorithm = new MessageHashDigestAlgorithm();
    VerifiableMessage<Challenge> verifiableMessage = getVerifiableMessageChallenge();
    assertTrue(verifiableMessage.verify(digestAlgorithm));
    byte[] data = verifiableMessage.serialize();
    VerifiableMessage<Challenge> deserialized = VerifiableMessage.deserialize(data, Challenge.deserializer());
    assertTrue(deserialized.verify(digestAlgorithm));
  }

  @Test
  public void testVerifyCorruptMessage() throws Exception {
    DigestAlgorithm digestAlgorithm = new MessageHashDigestAlgorithm();
    VerifiableMessage<Challenge> verifiableMessage = getVerifiableMessageChallenge();
    assertTrue(verifiableMessage.verify(digestAlgorithm));
    byte[] data = verifiableMessage.serialize();
    // Alter the message but make sure it's still parsable
    data[data.length-5] = 0;
    System.out.println(data);
    VerifiableMessage<Challenge> deserialized = VerifiableMessage.deserialize(data, Challenge.deserializer());
    assertFalse(deserialized.verify(digestAlgorithm));
  }

  private VerifiableMessage<Challenge> getVerifiableMessageChallenge() throws Exception {
    Challenge challenge = ChallengeTest.getDefaultChallenge();
    byte[] digest = new MessageHashDigestAlgorithm().getDigest(challenge.serialize());
    VerifiableMessage<Challenge> verifiableMessage =
        new VerifiableMessage<Challenge>(digest, challenge);
    return verifiableMessage;
  }

  private VerifiableMessage<Token> getVerifiableMessageToken() throws Exception {
    Token token = TokenTest.getDefaultToken();
    byte[] digest = new MessageHashDigestAlgorithm().getDigest(token.serialize());
    VerifiableMessage<Token> verifiableMessage =
        new VerifiableMessage<Token>(digest, token);
    return verifiableMessage;
  }
}
