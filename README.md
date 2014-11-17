crtauth-java
============

[![Master Build
Status](https://travis-ci.org/spotify/crtauth-java.svg?branch=master)](https://travis-ci.org/spotify/crtauth-java)

crtauth-java is a public key backed client/server authentication system written
in Java.

crtauth-java is the Java port of the original crtauth implementation that can be
found [here](https://github.com/spotify/crtauth). The java implementation is
fully wire compatible with the python version.

crtauth itself is a system for authenticating a user to a centralized server.
The initial use case is to create a convenient authentication for command line
tools that interacts with a central server without resorting to authentication
using a shared secret, such as a password.

If you are looking at building a client in java and would like to connect to a local
ssh-agent, code that implements this is available in the 
[crtauth-java-agent-signer](https://github.com/spotify/crtauth-java-agent-signer) project.   

License
-------

crtauth-java is free software, this code is released under the Apache Software
License, version 2. The original code is written by Federico Piccinini with
contributions from Noa Resare, John-John Tedro, Martin Parm and Nic Cope.

All code is Copyright (c) 2014 Spotify AB
