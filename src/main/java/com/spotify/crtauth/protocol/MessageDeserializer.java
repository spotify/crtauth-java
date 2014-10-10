package com.spotify.crtauth.protocol;

import com.spotify.crtauth.exceptions.DeserializationException;

/**
 * Interface that acts as a gateway to deserialization functions for a specific type.
 *
 * The common pattern is to add a <code>private static final</code> field of an
 * instance of MessageDeserializer<T>, and make it accessible through T#deserializer().
 *
 * @author udoprog
 * @param <T>
 * @see Challenge#deserializer()
 * @see Response#deserializer()
 * @see Token#deserializer()
 */
public interface MessageDeserializer<T extends XdrSerializable> {
  T deserialize(byte[] data) throws DeserializationException;
}
