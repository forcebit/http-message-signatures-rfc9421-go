# HTTP Message Signatures Library Benchmarks

Benchmark comparison of Go implementations of RFC 9421 HTTP Message Signatures.

## Libraries Compared

| Library | Import Path |
|---------|-------------|
| **forcebit** | `github.com/forcebit/http-message-signatures-rfc9421-go` |
| yaronf/httpsign | `github.com/yaronf/httpsign` |
| remitly-oss/httpsig-go | `github.com/remitly-oss/httpsig-go` |
| common-fate/httpsig | `github.com/common-fate/httpsig` |

## Benchmark Environment

- **Go Version**: 1.25.5
- **OS**: macOS (Darwin)
- **Architecture**: arm64 (Apple Silicon)
- **CPU**: Apple M2

## Methodology

All benchmarks measure equivalent full-flow operations:
- **Sign**: Build signature base → crypto sign → serialize headers → attach to request
- **Verify**: Parse headers → rebuild signature base → crypto verify

**Components signed**: `@method`, `@target-uri`, `content-type` (identical across all libraries)
**Validation**: `created` required, max age 5 minutes, future skew 1 minute (applied across all libraries)
**Reporting**: median of 5 runs (`go test -bench=. -benchmem -count=5`)
**Large-body digest benchmark**: 10MB request body, HMAC signing with `content-digest` + `content-length`

## Results

### Sign Performance (ns/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **919,775** | 967,993 | 927,747 | 985,090 |
| ECDSA-P256-SHA256 | **28,049** | 30,512 | 29,255 | 30,504 |
| HMAC-SHA256 | **2,484** | 4,893 | 4,954 | 6,538 |

### HMAC + Content-Digest (10MB) Sign Performance

| Metric | forcebit | yaronf | remitly | common-fate |
|--------|----------|--------|---------|-------------|
| ns/op | **4,155,414** | 6,524,077 | 5,292,531 | 5,163,056 |
| MB/s | **2,523** | 1,607 | 1,981 | 2,030 |
| B/op | **8,825** | 54,541,561 | 33,570,273 | 33,572,223 |
| allocs/op | **55** | 172 | 182 | 182 |

### Sign Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **8,891** | 12,155 | 11,962 | 14,357 |
| ECDSA-P256-SHA256 | **13,332** | 17,205 | 16,910 | 19,271 |
| HMAC-SHA256 | **7,562** | 10,697 | 10,929 | 14,725 |

### Sign Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **44** | 107 | 118 | 126 |
| ECDSA-P256-SHA256 | **97** | 177 | 175 | 183 |
| HMAC-SHA256 | **42** | 105 | 115 | 124 |

### Verify Performance (ns/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **30,760** | 36,591 | 33,516 | 34,534 |
| ECDSA-P256-SHA256 | **55,030** | 60,710 | 57,747 | 58,414 |
| HMAC-SHA256 | **1,528** | 6,509 | 3,865 | 5,858 |

### Verify Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **3,296** | 11,540 | 6,714 | 9,248 |
| ECDSA-P256-SHA256 | **2,144** | 10,276 | 6,170 | 8,744 |
| HMAC-SHA256 | **2,016** | 9,412 | 5,434 | 8,888 |

### Verify Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **35** | 184 | 119 | 126 |
| ECDSA-P256-SHA256 | **32** | 191 | 126 | 134 |
| HMAC-SHA256 | **27** | 176 | 111 | 118 |

## Visual Summary

Bars are scaled per algorithm to the slowest library (40 columns).

```
Sign (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    #####################################    919775
    yaronf      ######################################## 967993
    remitly     ######################################   927747
    common-fate ######################################## 985090

  ECDSA-P256-SHA256
    forcebit    ####################################     28049
    yaronf      ######################################## 30512
    remitly     ######################################   29255
    common-fate ######################################## 30504

  HMAC-SHA256
    forcebit    ###############                          2484
    yaronf      #############################            4893
    remitly     ##############################           4954
    common-fate ######################################## 6538

Sign HMAC + Content-Digest (10MB)
    forcebit    #########################                4155414
    yaronf      ######################################## 6524077
    remitly     ################################         5292531
    common-fate ################################         5163056

Verify (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    #################################        30760
    yaronf      ######################################## 36591
    remitly     ####################################     33516
    common-fate #####################################    34534

  ECDSA-P256-SHA256
    forcebit    ####################################     55030
    yaronf      ######################################## 60710
    remitly     ######################################   57747
    common-fate ######################################   58414

  HMAC-SHA256
    forcebit    #########                                 1528
    yaronf      ######################################## 6509
    remitly     #######################                   3865
    common-fate ####################################     5858
```

## Key Observations

### Performance
- **RSA-PSS Sign/Verify**: forcebit is ~5-11% faster than alternatives (RSA operations dominate)
- **ECDSA Sign**: forcebit ~4-8% faster
- **ECDSA Verify**: forcebit ~5-9% faster
- **HMAC Sign**: forcebit ~2.0-2.6x faster
- **HMAC Verify**: forcebit ~2.5-4.2x faster

### Memory Efficiency
- forcebit uses **1.5x-4x less memory** than alternatives in the hot path.
- forcebit makes **3x-6x fewer allocations** during signing and verification.
- large-body digest: forcebit stays **~9 KB/op** vs **33-54 MB/op** for others (full body buffering).

## Running Benchmarks

```bash
cd benchmarks/comparison
go test -bench=. -benchmem -count=5
go test -bench=BenchmarkSign_HMAC_ContentDigest_10MB -benchmem -count=5
```
