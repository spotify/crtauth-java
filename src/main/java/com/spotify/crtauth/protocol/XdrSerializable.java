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

import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.SerializationException;

/**
 * This interface represents any data type that has the capability of serializing or
 * deserializing itself using XDR as the coded for serialized data. Unless stated differently,
 * {@code XdrSerializable} objects are not thread-safe. XdrSerializable objects should be
 * immutable.
 */
public interface XdrSerializable {
  /**
   * Return the serialized representation of an object.
   * @return A byte array that contains a serialized representation of the object.
   * @throws SerializationException If the object cannot be serialized.
   */
  public byte[] serialize() throws SerializationException;

  /**
   * Produce an object out of its serialized representation.
   * @param bytes The serialized representation of an object.
   * @return A new object of the same type as the object that is performing the deserialization.
   *    Note that since {@code XdrSerializable} objects are immutable, the result of this operation
   *    MUST always be a new object.
   * @throws DeserializationException If the serialized representation cannot be translated back
   *    to an object (for example, if there is a type mismatch).
   */
  public XdrSerializable deserialize(byte[] bytes) throws DeserializationException;
}
