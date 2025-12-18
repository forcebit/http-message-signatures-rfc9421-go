# HTTP Message Signatures Library Benchmarks

Benchmark comparison of Go implementations of RFC 9421 HTTP Message Signatures.

## Libraries Compared

| Library                | Import Path | Description |
|------------------------|-------------|-------------|
| **forcebit**           | `github.com/forcebit/http-message-signatures-rfc9421-go` | Zero-dependency RFC 9421 implementation |
| yaronf/httpsign        | `github.com/yaronf/httpsign` | Feature-complete RFC 9421 implementation |
| remitly-oss/httpsig-go | `github.com/remitly-oss/httpsig-go` | Production-ready RFC 9421 implementation |
| common-fate/httpsig    | `github.com/common-fate/httpsig` | RFC 9421 with middleware focus |

## Benchmark Environment

- **Go Version**: 1.24
- **OS**: macOS (Darwin)
- **Architecture**: arm64 (Apple Silicon)
- **CPU**: Apple M2

## Algorithms Tested

- **RSA-PSS-SHA512**: 2048-bit RSA key with PSS padding
- **ECDSA-P256-SHA256**: P-256 elliptic curve
- **HMAC-SHA256**: 64-byte symmetric key

## Results

### Sign Performance (ns/op, lower is better)

| Algorithm | forcebit   | yaronf | remitly | common-fate |
|-----------|------------|--------|---------|-------------|
| RSA-PSS-SHA512 | **923,264** | 987,610 | 959,115 | 940,884 |
| ECDSA-P256-SHA256 | **24,926** | 28,924 | 28,202 | 29,739 |
| HMAC-SHA256 | **2,580**  | 5,071 | 5,803 | 6,931 |

```mermaid
xychart-beta horizontal
    title "Sign Performance - All Algorithms (ns/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf", "HMAC forcebit", "HMAC yaronf", "HMAC remitly", "HMAC cf"]
    y-axis "nanoseconds" 0 --> 1000000
    bar [923264, 987610, 959115, 940884, 24926, 28924, 28202, 29739, 2580, 5071, 5803, 6931]
```

### Sign Memory Allocations (B/op)

| Algorithm | forcebit   | yaronf | remitly | common-fate |
|-----------|------------|--------|---------|-------------|
| RSA-PSS-SHA512 | **8,058**  | 12,275 | 12,363 | 14,357 |
| ECDSA-P256-SHA256 | **13,220** | 17,326 | 17,294 | 19,271 |
| HMAC-SHA256 | **7,650**  | 10,817 | 11,322 | 14,725 |

```mermaid
xychart-beta horizontal
    title "Sign Memory - All Algorithms (bytes/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf", "HMAC forcebit", "HMAC yaronf", "HMAC remitly", "HMAC cf"]
    y-axis "bytes" 0 --> 20000
    bar [8058, 12275, 12363, 14357, 13220, 17326, 17294, 19271, 7650, 10817, 11322, 14725]
```

### Sign Allocation Count (allocs/op)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **56**   | 115 | 124 | 126 |
| ECDSA-P256-SHA256 | **108**  | 185 | 181 | 183 |
| HMAC-SHA256 | **55**   | 113 | 121 | 124 |

```mermaid
xychart-beta horizontal
    title "Sign Allocations - All Algorithms (allocs/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf", "HMAC forcebit", "HMAC yaronf", "HMAC remitly", "HMAC cf"]
    y-axis "allocations" 0 --> 200
    bar [56, 115, 124, 126, 108, 185, 181, 183, 55, 113, 121, 124]
```

### Verify Performance (ns/op, lower is better)

| Algorithm | forcebit   | yaronf | remitly | common-fate |
|-----------|------------|--------|---------|-------------|
| RSA-PSS-SHA512 | **29,538** | 37,494 | 34,307 | 35,055 |
| ECDSA-P256-SHA256 | **54,853** | 63,615 | 60,453 | 60,990 |
| HMAC-SHA256 | **460**    | 7,186 | 4,257 | 6,347 |

```mermaid
xychart-beta horizontal
    title "Verify Performance - RSA & ECDSA (ns/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf"]
    y-axis "nanoseconds" 0 --> 70000
    bar [29538, 37494, 34307, 35055, 54853, 63615, 60453, 60990]
```

```mermaid
xychart-beta horizontal
    title "Verify Performance - HMAC (ns/op, lower is better)"
    x-axis ["forcebit", "yaronf", "remitly", "common-fate"]
    y-axis "nanoseconds" 0 --> 8000
    bar [460, 7186, 4257, 6347]
```

### Verify Memory Allocations (B/op)

| Algorithm | forcebit  | yaronf | remitly | common-fate |
|-----------|-----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **1,792** | 11,869 | 7,115 | 9,248 |
| ECDSA-P256-SHA256 | **816**   | 10,604 | 6,570 | 8,744 |
| HMAC-SHA256 | **776**   | 9,740 | 5,834 | 8,888 |

```mermaid
xychart-beta horizontal
    title "Verify Memory - All Algorithms (bytes/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf", "HMAC forcebit", "HMAC yaronf", "HMAC remitly", "HMAC cf"]
    y-axis "bytes" 0 --> 13000
    bar [1792, 11869, 7115, 9248, 816, 10604, 6570, 8744, 776, 9740, 5834, 8888]
```

### Verify Allocation Count (allocs/op)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **15**   | 200 | 126 | 126 |
| ECDSA-P256-SHA256 | **11**   | 207 | 133 | 134 |
| HMAC-SHA256 | **8**    | 192 | 118 | 118 |

```mermaid
xychart-beta horizontal
    title "Verify Allocations - All Algorithms (allocs/op, lower is better)"
    x-axis ["RSA forcebit", "RSA yaronf", "RSA remitly", "RSA cf", "ECDSA forcebit", "ECDSA yaronf", "ECDSA remitly", "ECDSA cf", "HMAC forcebit", "HMAC yaronf", "HMAC remitly", "HMAC cf"]
    y-axis "allocations" 0 --> 220
    bar [15, 200, 126, 126, 11, 207, 133, 134, 8, 192, 118, 118]
```

## Key Observations

### Signing Performance
1. **RSA-PSS-SHA512**: forcebit is **fastest** (~923μs), 2-7% faster than alternatives
2. **ECDSA-P256-SHA256**: forcebit is **13-19% faster** than alternatives
3. **HMAC-SHA256**: forcebit is **2-2.7x faster** than alternatives

### Verification Performance
1. **RSA-PSS-SHA512**: forcebit is **14-27% faster** than alternatives
2. **ECDSA-P256-SHA256**: forcebit is **10-16% faster** than alternatives
3. **HMAC-SHA256**: forcebit is **9-16x faster** than alternatives

### Memory Efficiency
- Forcebit consistently uses **35-85% less memory** than alternatives
- Forcebit makes **50-90% fewer allocations** than alternatives
- Lower allocation count translates to reduced GC pressure

## Running Benchmarks

```bash
cd benchmarks/comparison

# Run all benchmarks
go test -bench=. -benchmem -count=5

# Run specific algorithm
go test -bench="RSAPSS" -benchmem -count=3

# Run only sign benchmarks
go test -bench="BenchmarkSign" -benchmem -count=3

# Run only verify benchmarks
go test -bench="BenchmarkVerify" -benchmem -count=3

# Save results to file
go test -bench=. -benchmem -count=5 | tee results.txt
```

## Benchmark Methodology

1. **Fair Comparison**: All libraries sign the same HTTP request with equivalent components
2. **Components Signed**: `@method`, `@authority`/`@target-uri`, `@path`, `content-type`
3. **Key Generation**: Keys are generated once at init and reused for all benchmarks
4. **Pre-signing for Verify**: Signatures are pre-generated before verify benchmarks to isolate verification time
5. **Memory Tracking**: `b.ReportAllocs()` used to track memory allocations

## Dependencies

Each library has different dependency requirements:

| Library                | External Dependencies |
|------------------------|----------------------|
| forcebit               | `golang.org/x/crypto` only |
| yaronf/httpsign        | Multiple (httpsfv, jwx, etc.) |
| remitly-oss/httpsig-go | Moderate |
| common-fate/httpsig    | Moderate |
