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

import com.google.common.io.BaseEncoding;
import com.spotify.crtauth.digest.MessageHashDigestAlgorithm;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.assertArrayEquals;

public class ResponseTest extends XdrSerializableTest<Response> {

  @Override
  protected Response getInstance() throws Exception {
    Challenge challenge = ChallengeTest.getDefaultChallenge();
    VerifiableMessage<Challenge> verifiableChallenge =
        new VerifiableMessage.Builder<Challenge>(Challenge.class)
            .setPayload(challenge)
            .setDigest(new MessageHashDigestAlgorithm().getDigest(challenge.serialize()))
            .build();
    byte[] signature = new byte[20];
    Random random = new Random();
    random.setSeed(0);
    random.nextBytes(signature);
    return new Response.Builder()
        .setVerifiableChallenge(verifiableChallenge)
        .setSignature(signature)
        .build();
  }

  @Test
  public void testSerializeResponse() throws Exception {
    final String verifiableChallengeBytes = "dgAAAE+FcZcDQxeHvLSj6zF81+rVg9cRAAAARGMAAAB/zYRBItuF" +
            "iUkt017idcrCU7TYolF8BYJRfAWYAAAABttlotT5EAAAAAAAC3NlcnZlcl9uYW1lAAAAAAR0ZXN0";
    final String signature = "Z/LbU01waGEK29BXCHKQYEaXeZcEVuCHGUyrZhxX8a5zX63I9XbART0nUic507YH98Y" +
        "OSBtR44IxIa8Zj0fDufD7+lcec7txVMcr2I0cA7/Rugy1biKQvUmLHb4bgA00HxVAGKTaKytZM15dZ9KQQU9SkDv" +
        "1ay9Izm/gxISJ+2wC7E23BRqpdBM/x/w8kCuAhqK087wIf6FoA3gH9sbquWqMzRzkj+FwUzIXkPWHGM6S4dD6FVl" +
        "mpnSAiE8PygaQzPkCf28vCbC8Ugqe1P86dnKoBxa1Al/PgaHf7nvgmu2rRd7lBw7aPOc1BHCbGO6JFCt07+XuGTS" +
        "NJ+kL0FBG+w==";
    final String expected = "cgAAAAAAAQBn8ttTTXBoYQrb0FcIcpBgRpd5lwRW4IcZTKtmHFfxrnNfrcj1dsBFPSdS" +
        "JznTtgf3xg5IG1HjgjEhrxmPR8O58Pv6Vx5zu3FUxyvYjRwDv9G6DLVuIpC9SYsdvhuADTQfFUAYpNorK1kzXl1n" +
        "0pBBT1KQO/VrL0jOb+DEhIn7bALsTbcFGql0Ez/H/DyQK4CGorTzvAh/oWgDeAf2xuq5aozNHOSP4XBTMheQ9YcY" +
        "zpLh0PoVWWamdICITw/KBpDM+QJ/by8JsLxSCp7U/zp2cqgHFrUCX8+Bod/ue+Ca7atF3uUHDto85zUEcJsY7okU" +
        "K3Tv5e4ZNI0n6QvQUEb7AAAAYHYAAABPhXGXA0MXh7y0o+sxfNfq1YPXEQAAAERjAAAAf82EQSLbhYlJLdNe4nXK" +
        "wlO02KJRfAWCUXwFmAAAAAbbZaLU+RAAAAAAAAtzZXJ2ZXJfbmFtZQAAAAAEdGVzdA==";
    final BaseEncoding encoding = BaseEncoding.base64();
    VerifiableMessage<Challenge> verifiableChallenge =
        VerifiableMessage.getDefaultInstance(Challenge.class)
            .deserialize(encoding.decode(verifiableChallengeBytes));
    Response response = new Response.Builder()
        .setVerifiableChallenge(verifiableChallenge)
        .setSignature(encoding.decode(signature))
        .build();
    assertArrayEquals(response.serialize(), encoding.decode(expected));
  }
}
