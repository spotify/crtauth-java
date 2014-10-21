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

import com.google.common.base.Preconditions;
import com.spotify.crtauth.digest.VerifiableDigestAlgorithm;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.SerializationException;
import com.spotify.crtauth.utils.TimeIntervals;
import com.spotify.crtauth.utils.TimeSupplier;

import java.util.Arrays;

public class Token {
  private static final byte MAGIC = 't';

  private final int validFrom;
  private final int validTo;
  private final String userName;

  public Token(int validFrom, int validTo, String userName) {
    Preconditions.checkArgument(validFrom < validTo, "negative lifespan of Token");
    Preconditions.checkNotNull(userName);
    Preconditions.checkArgument(!userName.isEmpty(), "Field 'userName' can not be empty");
    this.validFrom = validFrom;
    this.validTo = validTo;
    this.userName = userName;
  }

  public boolean isExpired(TimeSupplier timeSupplier) {
    return TimeIntervals.isExpired(validFrom, validTo, timeSupplier);
  }

  public int getValidFrom() {
    return validFrom;
  }

  public int getValidTo() {
    return validTo;
  }

  public String getUserName() {
    return this.userName;
  }

  public static Token deserialize(byte[] data) throws DeserializationException {
    return doDeserialize(new MiniMessagePack.Unpacker(data));
  }

  public static Token deserializeAuthenticated(byte[] data, byte[] hmac_secret)
      throws DeserializationException, InvalidInputException {
    MiniMessagePack.Unpacker unpacker = new MiniMessagePack.Unpacker(data);
    Token c = doDeserialize(unpacker);
    VerifiableDigestAlgorithm verifiableDigest = new VerifiableDigestAlgorithm(hmac_secret);
    byte[] digest = verifiableDigest.getDigest(data, 0, unpacker.getBytesRead());
    if (!Arrays.equals(digest, unpacker.unpackBin())) {
      throw new InvalidInputException("HMAC validation failed");
    }
    return c;
  }

  private static Token doDeserialize(MiniMessagePack.Unpacker unpacker) throws DeserializationException {
    MessageParserHelper.parseVersionMagic(MAGIC, unpacker);
    return new Token(
        unpacker.unpackInt(),   // validFrom
        unpacker.unpackInt(),   // validTo
        unpacker.unpackString() // userName
    );
  }

  public byte[] serialize(byte[] hmac_secret) throws SerializationException {
    MiniMessagePack.Packer packer = new MiniMessagePack.Packer();
    packer.pack((byte) 0x01);
    packer.pack(MAGIC);
    packer.pack(validFrom);
    packer.pack(validTo);
    packer.pack(userName);
    byte[] bytes = packer.getBytes();
    byte[] mac = new VerifiableDigestAlgorithm(hmac_secret).getDigest(bytes, 0, bytes.length);
    packer.pack(mac);
    return packer.getBytes();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Token token = (Token) o;

    if (validFrom != token.validFrom) return false;
    if (validTo != token.validTo) return false;
    return userName.equals(token.userName);

  }

  @Override
  public int hashCode() {
    int result = validFrom;
    result = 31 * result + validTo;
    result = 31 * result + userName.hashCode();
    return result;
  }
}
