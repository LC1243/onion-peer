# Onion Peer

Project for the "Decentralized System Engineering" course.
Built on top of the homework solutions from Louis Chapuis for the CS-438 course (Homework 0 and 1).

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