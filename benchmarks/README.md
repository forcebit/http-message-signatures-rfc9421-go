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

## Results

### Sign Performance (ns/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **933,149** | 938,304 | 936,154 | 957,184 |
| ECDSA-P256-SHA256 | **30,150** | 31,888 | 30,990 | 32,815 |
| HMAC-SHA256 | **4,722** | 5,858 | 6,343 | 8,083 |

### Sign Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **11,147** | 12,154 | 11,962 | 14,357 |
| ECDSA-P256-SHA256 | **15,269** | 17,206 | 16,910 | 19,271 |
| HMAC-SHA256 | **9,235** | 10,697 | 10,929 | 14,725 |

### Sign Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **102** | 107 | 118 | 126 |
| ECDSA-P256-SHA256 | **157** | 177 | 175 | 183 |
| HMAC-SHA256 | **101** | 105 | 115 | 124 |

### Verify Performance (ns/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **39,797** | 46,487 | 42,476 | 43,849 |
| ECDSA-P256-SHA256 | **62,191** | 67,297 | 68,756 | 65,038 |
| HMAC-SHA256 | **3,378** | 8,360 | 4,812 | 6,995 |

### Verify Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **6,208** | 11,540 | 6,715 | 9,248 |
| ECDSA-P256-SHA256 | **5,096** | 10,276 | 6,170 | 8,744 |
| HMAC-SHA256 | **4,952** | 9,412 | 5,434 | 8,888 |

### Verify Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **90** | 184 | 119 | 126 |
| ECDSA-P256-SHA256 | **88** | 191 | 126 | 134 |
| HMAC-SHA256 | **83** | 176 | 111 | 118 |

## Visual Summary

Bars are scaled per algorithm to the slowest library (40 columns).

```
Sign (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    #######################################  933149
    yaronf      #######################################  938304
    remitly     #######################################  936154
    common-fate ######################################## 957184

  ECDSA-P256-SHA256
    forcebit    #####################################    30150
    yaronf      #######################################  31888
    remitly     ######################################   30990
    common-fate ######################################## 32815

  HMAC-SHA256
    forcebit    #######################                  4722
    yaronf      #############################            5858
    remitly     ###############################          6343
    common-fate ######################################## 8083

Verify (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    ##################################       39797
    yaronf      ######################################## 46487
    remitly     #####################################    42476
    common-fate ######################################   43849

  ECDSA-P256-SHA256
    forcebit    ####################################     62191
    yaronf      #######################################  67297
    remitly     ######################################## 68756
    common-fate ######################################   65038

  HMAC-SHA256
    forcebit    ################                         3378
    yaronf      ######################################## 8360
    remitly     #######################                  4812
    common-fate #################################        6995
```

## Key Observations

### Performance
- **RSA-PSS Sign/Verify**: all libraries within ~14% (crypto dominated)
- **ECDSA Sign**: forcebit ~3-8% faster
- **ECDSA Verify**: forcebit ~4-10% faster
- **HMAC Sign**: forcebit ~19-42% faster
- **HMAC Verify**: forcebit ~30-60% faster

### Memory Efficiency
- forcebit uses 7-50% less memory than alternatives
- forcebit makes 4-54% fewer allocations

## Running Benchmarks

```bash
cd benchmarks/comparison
go test -bench=. -benchmem -count=5
```
