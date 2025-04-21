# Threshold ML-DSA and Threshold Raccoon with Identifiable Aborts Implementations

This repository contains implementations from the research paper:

**"Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with Identifiable Aborts"**  
*Giacomo Borin, Sofia Celi, Rafael del Pino, Thomas Espitau, Guilhem Niot, Thomas Prest*

This repository includes the following implementations:

- Threshold ML-DSA implementation based on Circl (Cloudflare) in `circl-main`.
- Enhanced T-Raccoon based on Lattigo in `traccoon-sign`.

We additionally provide our benchmarking tools:
- Threshold ML-DSA was evaluated with go-libp2p for LAN/WAN experiments, see `go-libp2p/examples/chat`.
- Threshold ML-DSA local benchmark tools are in `threshold-mldsa`.
- T-Raccoon was evaluated with the network tools in `traccoon-sign` for LAN/WAN, and local experiments.

We also include the parameter selection scripts for Threshold ML-DSA in `params`.

## Running Benchmarks

### Threshold ML-DSA Benchmarks

#### Local Benchmarks
Navigate to the `threshold-mldsa` directory and run:

```bash
cd threshold-mldsa
go run main.go type=d iter=<iterations> t=<threshold> n=<parties>
```

**Parameters:**
- `iter`: Number of iterations to average latencies over (use 1 for single run)
- `t`: Threshold value (number of parties required to sign)
- `n`: Total number of parties (maximum 6 parties allowed)

**Example:**
```bash
# Run 100 iterations with threshold 3 out of 5 parties
go run main.go type=d iter=100 t=3 n=5
```

#### Network Benchmarks (LAN/WAN)
Use the go-libp2p chat example for distributed experiments:

```bash
cd go-libp2p/examples/chat
go build
```

Then run on two different machines:
```bash
# On the first machine (server)
./chat -sp <PORT> -id 0

# On another machine (client)
./chat -d /ip4/<SERVER_IP>/tcp/<PORT>/p2p/<PEER_ID> -id 1
```

### Threshold Raccoon Benchmarks

#### Local Benchmarks
Navigate to the `traccoon-sign` directory and run:

```bash
cd traccoon-sign
go run main.go type=d iter=<iterations> t=<threshold> n=<parties>
```

**Parameters:**
- `iter`: Number of iterations to average latencies over (use 1 for single run)
- `t`: Threshold value (number of parties required to sign)
- `n`: Total number of parties

**Example:**
```bash
# Run 50 iterations with threshold 2 out of 4 parties
go run main.go type=d iter=50 t=2 n=4
```

#### Network Benchmarks (LAN/WAN)
For distributed experiments, run the same command on different machines with different party IDs:

```bash
# On machine 1 (party 0)
go run main.go type=0 iter=10 t=2 n=2

# On machine 2 (party 1)
go run main.go type=1 iter=10 t=2 n=2
```

## Prerequisites

- Go 1.19 or later
- For Threshold ML-DSA: The modified Circl library in `circl-main`
- For Threshold Raccoon: Lattigo v5 library

## Warning

**These implementations are academic proof-of-concept prototypes, have not received careful code review, and are not ready for production use.**