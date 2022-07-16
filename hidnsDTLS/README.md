# hiDNS-over-DTLS proxy
hiDNS over DTLS1.2

About
=====

This module contains a client proxy and a server proxy. The local client proxy will accept hiDNS UDP plaintext query and send it through DTLS to remote server proxy. The local server proxy will accept DTLS cyphertext query and forward it to hiDNS server. Vice versa for the hiDNS answer.

This module is implemented with reference to the these repositories:

- [pj19860304/DNS-over-DTLS](https://github.com/pj19860304/DNS-over-DTLS).
- [tidwall/hashmap.c](https://github.com/tidwall/hashmap.c).

Usage
============
For hiDNS stub resolver, just run the client proxy. For recursive caching server or authoritative server, both client proxy and server proxy should be run with the hiDNS server daemon.

For the server proxy, a private key and certificate should be configured. (TBD)

Requirements
============

Development Packages of: openssl
```bash
sudo apt install libssl-dev
```

