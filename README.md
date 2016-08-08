# REMOTE VEHICLE INTERFACE
Remote Vehicle Interface (RVI) provides an architecture which, through its
specified components, enables connected vehicles and other devices to form a
secured distributed, sparsely connected peer-to-peer network. In particular,
local services can be registered to enable remote invocation, with the proper
credentials. In general, RVI provides an intermediary between less trusted
remote sources and more trusted internal sources, while limiting direct
communication channels.

`rvi_lib` will provide a client implementation in C. This is supplemental to
[RVI Core](https://github.com/GENIVI/rvi_core), which adds a variety of
capabilities including listening for incoming connections.

# STANDARDS USED

1. [JSON](http://www.json.org/)
2. [base64url](https://en.wikipedia.org/wiki/Base64)
3. [JSON Web Token (JWT)](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32)
4. [X.509 Certificates](https://en.wikipedia.org/wiki/X.509)
5. [Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc5246)

# EXTERNAL DEPENDENCIES

`rvi_lib` depends on the following libraries:

1. [C Standard Library](https://www-s.acm.illinois.edu/webmonkeys/book/c_guide/index.html)
2. [OpenSSL](https://www.openssl.org/)
3. [Jansson](http://www.digip.org/jansson/)
4. [LibJWT](https://github.com/benmcollins/libjwt)
