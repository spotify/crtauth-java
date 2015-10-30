# crtauth-java


[![Master Build Status](https://travis-ci.org/spotify/crtauth-java.svg?branch=master)][3]

crtauth-java is a public key backed client/server authentication system written
in Java.

crtauth-java is the Java port of the original crtauth implementation that can be
found [here][4]. The java implementation is
fully wire compatible with the python version.

crtauth itself is a system for authenticating a user to a centralized server.
The initial use case is to create a convenient authentication for command line
tools that interacts with a central server without resorting to authentication
using a shared secret, such as a password.

If you are looking at building a client in Java and would like to connect to a local
ssh-agent, here's how:


```java
final AgentSigner signer = new AgentSigner();
final byte[] signed = signer.sign(new byte[] {1, 2, 3, 4}, new Fingerprint(publicKey));
```

## License


crtauth-java is free software, this code is released under the Apache Software
License, version 2. The original code is written by Federico Piccinini with
contributions from Noa Resare, John-John Tedro, Martin Parm and Nic Cope.

All code is Copyright (c) 2015 Spotify AB

  [1]: https://github.com/jnr/jnr-unixsocket
  [2]: http://mvnrepository.com/artifact/commons-codec/commons-codec
  [3]: https://travis-ci.org/spotify/crtauth-java
  [4]: https://github.com/spotify/crtauth
  [5]: https://github.com/spotify/crtauth-java-agent-signer
  [6]: https://github.com/spotify/crtauth-java-agent-signer-apache
  [7]: https://mina.apache.org/downloads-sshd.html
  [8]: https://tomcat.apache.org/download-native.cgi

