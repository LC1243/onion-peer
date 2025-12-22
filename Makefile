export GLOG = no
export BINLOG = warn
export HTTPLOG = warn
export GORACE = halt_on_error=1
export GNODES = 10
# how many benchmark iterations to average on
export BENCHTIME = "10x"
export PEER_BIN_PATH = dummy

all: lint vet test

test: test_hw0 test_hw1 test_hw2 test_hw3

test_hw0: test_unit_hw0 test_int_hw0
test_hw1: test_unit_hw1 test_int_hw1
test_hw2: test_unit_hw2 test_int_hw2
test_hw3: test_unit_hw3 test_int_hw3
test_tor: test_unit_tor test_int_tor

test_unit_tor:
	go test -timeout 7m -v -race -run Test_TOR ./peer/tests/unit

test_int_tor:
	go test -timeout 7m -v -race -run Test_TOR ./peer/tests/integration

test_unit_hw0:
	go test -timeout 2m -v -race -run Test_HW0 ./peer/tests/unit

test_unit_hw1:
	go test -timeout 2m -v -race -run Test_HW1 ./peer/tests/unit

test_unit_hw2:
	go test -timeout 2m -v -race -run Test_HW2 ./peer/tests/unit

test_unit_hw3:
	go test -timeout 2m -v -race -run Test_HW3 ./peer/tests/unit

test_int_hw0:
	go test -timeout 5m -v -race -run Test_HW0 ./peer/tests/integration

test_int_hw1:
	go test -timeout 5m -v -race -run Test_HW1 ./peer/tests/integration

test_int_hw2:
	go test -timeout 5m -v -race -run Test_HW2 ./peer/tests/integration

test_int_hw3:
	go test -timeout 5m -v -race -run Test_HW3 ./peer/tests/integration

# JSONIFY is set to "-json" in CI to format for GitHub, empty for displaying locally
# || true allows to ignore error code and allow for smoother output logging
test_bench_hw1:
	@GLOG=no go test -v ${JSONIFY} -timeout 15m -run Test_HW1 -v -count 1 --tags=performance -benchtime=${BENCHTIME} ./peer/tests/perf/ || true

test_bench_hw2:
	@GLOG=no go test -v ${JSONIFY} -timeout 21m -run Test_HW2 -v -count 1 --tags=performance -benchtime=3x ./peer/tests/perf/ || true

test_bench_hw3: test_bench_hw3_tlc test_bench_hw3_consensus

test_bench_hw3_tlc:
	@GLOG=no go test -v ${JSONIFY} -timeout 15s -run Test_HW3_BenchmarkTLC -v -count 1 --tags=performance -benchtime=${BENCHTIME} ./peer/tests/perf/ || true

test_bench_hw3_consensus:
	@GLOG=no go test -v ${JSONIFY} -timeout 12m -run Test_HW3_BenchmarkConsensus -v -count 1 --tags=performance -benchtime=${BENCHTIME} ./peer/tests/perf/ || true

test_bench_tor:
	@GLOG=no go test -v ${JSONIFY} -timeout 30m -run Test_Plot_And_Benchmark_TOR -v -count 1 --tags=performance ./peer/tests/perf/ || true

test_reproduce_tor:
	@GLOG=no PLOT=1 go test -v ${JSONIFY} -timeout 30m -run Test_Plot_And_Benchmark_TOR -v -count 1 --tags=performance ./peer/tests/perf/ || true

lint:
	# Coding style static check.
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.1
	@go mod tidy
	golangci-lint run

vet:
	go vet ./...

# CLI targets
cli-build:
	go build -o tor-cli ./cli/cli.go

cli-run: cli-build
	./tor-cli

cli-clean:
	rm -f tor-cli

.PHONY: cli-build cli-run cli-clean
