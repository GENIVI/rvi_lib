# REMOTE VEHICLE INTERFACE {#mainpage}
Remote Vehicle Interface (RVI) provides an architecture which, through its
specified components, enables connected vehicles and other devices to form a
secured distributed, sparsely connected peer-to-peer network. In particular,
local services can be registered to enable remote invocation only when the peer
presents appropriate credentials. In general, RVI provides an intermediary
between less trusted remote sources and more trusted internal sources, while
limiting direct communication channels.

`rvi_lib` provides a client implementation in C. This is supplemental to
[RVI Core](https://github.com/GENIVI/rvi_core), which adds a variety of
capabilities including listening for incoming connections.

# Standards Used

1. [JSON](http://www.json.org/)
2. [base64url](https://en.wikipedia.org/wiki/Base64)
3. [JSON Web Token (JWT)](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32)
4. [X.509 Certificates](https://en.wikipedia.org/wiki/X.509)
5. [Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc5246)

# Build Requirements

`rvi_lib` depends on the following libraries:

1. [C Standard Library](https://www-s.acm.illinois.edu/webmonkeys/book/c_guide/index.html)
2. [OpenSSL](https://www.openssl.org/)
3. [Jansson](http://www.digip.org/jansson/)
4. [LibJWT](https://github.com/benmcollins/libjwt) †

† Please note that this project contains modified code for libjwt to support
public-private key cryptography for JSON Web Tokens. As such, no further
downloads are required for libJWT at the present time. However, this is subject
to change when the upstream project supports tokens encoded using RS256.

`rvi_lib` does not currently depend on the following but may add any or all to
support interoperability with [RVI Core](https://github.com/GENIVI/rvi_core)
nodes:

5. [mpack](http://ludocode.github.io/mpack/)

# Documentation
[GitHub pages](http://genivi.github.io/rvi_lib)

# Build Instructions

