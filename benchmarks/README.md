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
| RSA-PSS-SHA512 | **1,060,530** | 1,151,409 | 1,133,361 | 1,155,691 |
| ECDSA-P256-SHA256 | **29,065** | 31,647 | 31,369 | 32,649 |
| HMAC-SHA256 | **4,520** | 5,761 | 6,086 | 8,111 |

### HMAC + Content-Digest (10MB) Sign Performance

| Metric | forcebit | yaronf | remitly | common-fate |
|--------|----------|--------|---------|-------------|
| ns/op | **4,325,239** | 7,099,148 | 5,728,957 | 6,401,220 |
| MB/s | **2,424** | 1,477 | 1,830 | 1,638 |
| B/op | **10,778** | 54,541,576 | 33,570,286 | 33,572,233 |
| allocs/op | **134** | 172 | 182 | 182 |

### Sign Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **11,148** | 12,154 | 11,962 | 14,357 |
| ECDSA-P256-SHA256 | **15,269** | 17,206 | 16,910 | 19,271 |
| HMAC-SHA256 | **9,211** | 10,697 | 10,929 | 14,725 |

### Sign Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **102** | 107 | 118 | 126 |
| ECDSA-P256-SHA256 | **157** | 177 | 175 | 183 |
| HMAC-SHA256 | **100** | 105 | 115 | 124 |

### Verify Performance (ns/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **39,422** | 44,798 | 41,072 | 41,956 |
| ECDSA-P256-SHA256 | **61,709** | 66,988 | 63,042 | 64,514 |
| HMAC-SHA256 | **3,478** | 7,928 | 4,789 | 6,829 |

### Verify Memory (B/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **6,208** | 11,540 | 6,715 | 9,248 |
| ECDSA-P256-SHA256 | **5,096** | 10,276 | 6,170 | 8,744 |
| HMAC-SHA256 | **4,928** | 9,412 | 5,434 | 8,888 |

### Verify Allocations (allocs/op, lower is better)

| Algorithm | forcebit | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **90** | 184 | 119 | 126 |
| ECDSA-P256-SHA256 | **88** | 191 | 126 | 134 |
| HMAC-SHA256 | **82** | 176 | 111 | 118 |

## Visual Summary

Bars are scaled per algorithm to the slowest library (40 columns).

```
Sign (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    #####################################    1060530
    yaronf      ######################################## 1151409
    remitly     #######################################  1133361
    common-fate ######################################## 1155691

  ECDSA-P256-SHA256
    forcebit    ####################################     29065
    yaronf      #######################################  31647
    remitly     ######################################   31369
    common-fate ######################################## 32649

  HMAC-SHA256
    forcebit    ######################                   4520
    yaronf      ############################             5761
    remitly     ##############################           6086
    common-fate ######################################## 8111

Sign HMAC + Content-Digest (10MB)
    forcebit    ########################                  4325239
    yaronf      ########################################  7099148
    remitly     ################################         5728957
    common-fate ####################################     6401220

Verify (ns/op, lower is better)
  RSA-PSS-SHA512
    forcebit    ###################################      39422
    yaronf      ######################################## 44798
    remitly     #####################################    41072
    common-fate #####################################    41956

  ECDSA-P256-SHA256
    forcebit    #####################################    61709
    yaronf      ######################################## 66988
    remitly     ######################################   63042
    common-fate #######################################  64514

  HMAC-SHA256
    forcebit    ##################                       3478
    yaronf      ######################################## 7928
    remitly     ########################                  4789
    common-fate ##################################       6829
```

## Key Observations

### Performance
- **RSA-PSS Sign/Verify**: all libraries within ~9-14% (crypto dominated)
- **ECDSA Sign**: forcebit ~7-11% faster
- **ECDSA Verify**: forcebit ~2-8% faster
- **HMAC Sign**: forcebit ~1.3-1.8x faster
- **HMAC Verify**: forcebit ~1.4-2.3x faster

### Memory Efficiency
- forcebit uses 7-50% less memory than alternatives
- forcebit makes 5-54% fewer allocations
- large-body digest: forcebit stays ~10 KB/op vs 32-54 MB/op for others

## Running Benchmarks

```bash
cd benchmarks/comparison
go test -bench=. -benchmem -count=5
go test -bench=BenchmarkSign_HMAC_ContentDigest_10MB -benchmem -count=5
```
