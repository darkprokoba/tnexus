# tnexus - A TCP/TLS Tunneling Service

tnexus exposes your TCP or TLS (including HTTPS) servers to the public Internet
even when you don't have a public IP address.

tnexus also allows you to expose multiple separate TLS services behind a single
TCP endpoint.

# Features
* High-performance non-blocking I/O backed by epoll or kqueue
* Multi-core support
* REST API for configuring listening endpoints and forwarding rules (the API can be disabled to reduce attack surface)
* Highly Secure (100% safe Rust)
* High throughput (most of the time tnexus just forwards bytes, i.e. it doesn't do TLS termination)
* SNI multiplexing of connections
* Reverse tunnels (connections from A to B when A has a public IP and B doesn't)
* Bi-directional connections when neither side has a public IP (all data forwarded thru a third party)
* MIT license

# Long-term plans
* TLS termination
* HTTP multiplexing (acting as an HTTP proxy)
* Multi-tenant API (multiple users can have their own set of forwarding rules)
* Make use of splice(2)
* TCP hole punching (bi-directional A to B connectivity when neither side has a public IP without forwarding all data thru a third party)
