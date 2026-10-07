# Onion Peer

An implementation of **Tor-inspired onion routing** built on top of Peerster, developed as the group project for the **CS-438: Decentralized Systems Engineering** course at EPFL.

The project explores the design and implementation of a decentralized anonymous communication system based on the ideas presented in:

> R. Dingledine, N. Mathewson, and P. Syverson, *[Tor: The Second-Generation Onion Router](https://www.usenix.org/conference/13th-usenix-security-symposium/tor-second-generation-onion-router)*, USENIX Security Symposium, 2004.

The system implements onion routing over the Peerster network, allowing messages to be routed through multiple intermediate nodes using layered encryption. The implementation includes **circuits and streams, rate limiting, fairness and congestion control, and rendezvous-based communication**.

The project also provides an interactive CLI for demonstrating the onion-routing functionality.

## AI usage

AI was used to refactor a lot of the code, add comments and debugging.
## Run the tests

To run all the `Tor-related` tests (unit and integration), run: 

```sh
make test_tor
```

You can also run them individually:
 
- unit tests: 
```sh
make test_unit_tor
```

- integration tests: 
```sh 
make test_int_tor
```

- performance tests: 
```sh
make test_bench_tor
```

You can also just run `make` to run all the tests, but it will also run the tests for homeworks 0 and 1.
### Reproducing the results

If you wish to reproduce the results of the performance tests, you can run: 

```sh
make test_reproduce_tor
```

## Code Coverage

To compute code coverage for our implementation:

```sh
go test ./peer/tests/...   -coverpkg=./peer/...   -coverprofile=peer.coverage.out
```

To visualize the coverage in HTML (for example using Firefox):

```sh
go tool cover -html=peer.coverage.out -o peer_coverage.html
firefox peer_coverage.html
```

## CLI

For an interactive command-line interface to demonstrate the Tor-like onion routing system:

```sh
make cli-run
```

See the [CLI README](cli/README.md) for detailed usage instructions and example scenarios.

## Project Background

This project was developed as part of the **CS-438 Decentralized Systems Engineering** group project at EPFL.

The course project required students to build a decentralized or distributed system on top of Peerster, based on existing research literature, and to design a corresponding testing and performance-evaluation methodology.

For the **Secure Routing** project track, the objective was to implement onion routing and Tor on top of Peerster and integrate it with Peerster's private-messaging functionality. The project specification identifies the following main components:

- Circuits and streams
- Rate limiting, fairness, and congestion control
- Rendezvous points and hidden services
- Unit and integration testing
- Performance evaluation based on circuit length, latency, throughput, and congestion/rate-limiting overhead
