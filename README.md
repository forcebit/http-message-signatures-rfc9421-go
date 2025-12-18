# HTTP Message Signatures (RFC 9421) for Go

![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/forcebit/http-message-signatures-rfc9421-go/badges/coverage.json)
[![Go Report Card](https://goreportcard.com/badge/github.com/forcebit/http-message-signatures-rfc9421-go)](https://goreportcard.com/report/github.com/forcebit/http-message-signatures-rfc9421-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A complete Go implementation of [RFC 9421 HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421) with support for signing, verification, and Content-Digest generation.

## Features

- **Full RFC 9421 Implementation** - Parse, sign, and verify HTTP message signatures
- **6 Signature Algorithms** - RSA-PSS, RSA PKCS#1 v1.5, ECDSA (P-256, P-384), Ed25519, HMAC-SHA256
- **7 Digest Algorithms** - SHA-2, SHA-3, BLAKE2b families
- **Zero External Dependencies** - Only `golang.org/x/crypto` for SHA-3/BLAKE2b
- **Streaming Support** - O(1) memory for large message bodies
- **RFC 8941 Parser** - Complete Structured Field Values implementation

## Installation

```bash
go get github.com/forcebit/http-message-signatures-rfc9421-go
```

**Requires:** Go 1.21+

## Quick Start

### Sign an HTTP Request

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "fmt"
    "net/http"

    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/base"
    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/parser"
    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/signing"
)

func main() {
    // Create request
    req, _ := http.NewRequest("POST", "https://example.com/api/resource", nil)
    req.Header.Set("Content-Type", "application/json")

    // Define components to sign
    components := []parser.ComponentIdentifier{
        {Name: "@method", Type: parser.ComponentDerived},
        {Name: "@path", Type: parser.ComponentDerived},
        {Name: "content-type", Type: parser.ComponentField},
    }

    // Set signature parameters
    created := int64(1618884473)
    alg := "ecdsa-p256-sha256"
    keyid := "my-key-id"
    params := parser.SignatureParams{
        Created:   &created,
        Algorithm: &alg,
        KeyID:     &keyid,
    }

    // Build signature base
    msg := base.WrapRequest(req)
    sigBase, _ := base.Build(msg, components, params)

    // Sign
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    algorithm, _ := signing.GetAlgorithm("ecdsa-p256-sha256")
    signature, _ := algorithm.Sign(sigBase, privateKey)

    fmt.Printf("Signature: %x\n", signature)
}
```

### Verify a Signature

```go
package main

import (
    "encoding/base64"
    "fmt"
    "net/http"

    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/base"
    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/parser"
    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/signing"
)

func VerifyRequest(req *http.Request, publicKey interface{}) error {
    // Parse signature headers
    signatureInput := req.Header.Get("Signature-Input")
    signatureHeader := req.Header.Get("Signature")

    parsed, err := parser.ParseSignatures(signatureInput, signatureHeader, sfv.DefaultLimits())
    if err != nil {
        return fmt.Errorf("parse error: %w", err)
    }

    // Get signature entry (assuming single signature labeled "sig1")
    sig, ok := parsed.Signatures["sig1"]
    if !ok {
        return fmt.Errorf("signature 'sig1' not found")
    }

    // Rebuild signature base
    msg := base.WrapRequest(req)
    sigBase, err := base.Build(msg, sig.CoveredComponents, sig.SignatureParams)
    if err != nil {
        return fmt.Errorf("build error: %w", err)
    }

    // Verify
    alg, _ := signing.GetAlgorithm(*sig.SignatureParams.Algorithm)
    return alg.Verify(sigBase, sig.SignatureValue, publicKey)
}
```

### Generate Content-Digest

```go
package main

import (
    "fmt"

    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
)

func main() {
    body := []byte(`{"hello": "world"}`)

    // Compute digest
    d, _ := digest.ComputeDigest(body, digest.AlgorithmSHA256)

    // Format as header value
    header, _ := digest.FormatContentDigest(map[string][]byte{
        digest.AlgorithmSHA256: d,
    })

    fmt.Println(header)
    // Output: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
}
```

### Streaming Digest (O(1) Memory)

```go
package main

import (
    "io"
    "os"

    "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/digest"
)

func main() {
    file, _ := os.Open("large-file.bin")
    defer file.Close()

    // Create streaming hasher
    h, _ := digest.NewDigester(digest.AlgorithmSHA512)

    // Stream through hasher (constant memory)
    io.Copy(h, file)

    // Get digest
    digestBytes := h.Sum(nil)
}
```

## Packages

| Package | Description |
|---------|-------------|
| `pkg/parser` | Parse Signature-Input and Signature headers |
| `pkg/base` | Build canonical signature base from HTTP messages |
| `pkg/signing` | Sign and verify with RFC 9421 algorithms |
| `pkg/digest` | Content-Digest generation and verification |
| `pkg/sfv` | RFC 8941 Structured Field Values parser |

## Supported Algorithms

### Signature Algorithms (RFC 9421 Section 3.3)

| Algorithm ID | Type | Key Type |
|--------------|------|----------|
| `rsa-pss-sha512` | RSA-PSS | *rsa.PrivateKey / *rsa.PublicKey |
| `rsa-v1_5-sha256` | RSA PKCS#1 v1.5 | *rsa.PrivateKey / *rsa.PublicKey |
| `ecdsa-p256-sha256` | ECDSA | *ecdsa.PrivateKey / *ecdsa.PublicKey (P-256) |
| `ecdsa-p384-sha384` | ECDSA | *ecdsa.PrivateKey / *ecdsa.PublicKey (P-384) |
| `ed25519` | EdDSA | ed25519.PrivateKey / ed25519.PublicKey |
| `hmac-sha256` | HMAC | []byte (min 16 bytes, recommended 32) |

### Digest Algorithms (Content-Digest)

| Algorithm ID | Family | Output Size |
|--------------|--------|-------------|
| `sha-256` | SHA-2 | 32 bytes |
| `sha-512` | SHA-2 | 64 bytes |
| `sha-512/256` | SHA-2 | 32 bytes |
| `sha3-256` | SHA-3 | 32 bytes |
| `sha3-512` | SHA-3 | 64 bytes |
| `blake2b-256` | BLAKE2b | 32 bytes |
| `blake2b-512` | BLAKE2b | 64 bytes |

Deprecated algorithms (MD5, SHA-1, etc.) are explicitly rejected.

## Derived Components

All RFC 9421 derived components are supported:

| Component | Description |
|-----------|-------------|
| `@method` | HTTP request method (GET, POST, etc.) |
| `@target-uri` | Full target URI |
| `@authority` | Host and port |
| `@scheme` | URI scheme (http, https) |
| `@request-target` | Request target from request line |
| `@path` | Absolute path component |
| `@query` | Query string with leading `?` |
| `@query-param` | Individual query parameter (requires `name`) |
| `@status` | Response status code |

## API Reference

### parser.ParseSignatures

```go
func ParseSignatures(signatureInput, signature string, limits sfv.Limits) (*ParsedSignatures, error)
```

Parses `Signature-Input` and `Signature` header values into structured data.

### base.Build

```go
func Build(msg HTTPMessage, components []parser.ComponentIdentifier, params parser.SignatureParams) ([]byte, error)
```

Constructs the canonical signature base per RFC 9421 Section 2.5.

### signing.GetAlgorithm

```go
func GetAlgorithm(id string) (Algorithm, error)
```

Returns a signing algorithm by its RFC 9421 identifier.

### digest.ComputeDigest

```go
func ComputeDigest(body []byte, algorithm string) ([]byte, error)
```

Computes a cryptographic digest of the body.

### digest.VerifyContentDigest

```go
func VerifyContentDigest(reader io.Reader, header string, requiredAlgorithms []string) error
```

Verifies Content-Digest header against streaming body (O(1) memory).

## Security

- **Constant-time comparison** for HMAC and digest verification
- **RSA key validation** - minimum 2048 bits required
- **Algorithm rejection** - deprecated algorithms explicitly rejected
- **DoS prevention** - configurable parser limits via `sfv.Limits`

## Benchmarks

Compared against other Go RFC 9421 implementations ([yaronf/httpsign](https://github.com/yaronf/httpsign), [remitly-oss/httpsig-go](https://github.com/remitly-oss/httpsig-go), [common-fate/httpsig](https://github.com/common-fate/httpsig)):

| Metric | Sign | Verify |
|--------|------|--------|
| **ECDSA-P256** | 15-18% faster | 10-16% faster |
| **HMAC-SHA256** | 1.8-2.4x faster | 9-16x faster |
| **Memory** | 40-85% less | 40-85% less |
| **Allocations** | 50-90% fewer | 50-90% fewer |

See [benchmarks/README.md](benchmarks/README.md) for detailed results and methodology.

## Testing

```bash
# Run all tests
go test ./...

# Run with race detector
go test ./... -race

# Run with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run fuzz tests
go test ./pkg/sfv/... -fuzz=FuzzParseDictionary -fuzztime=30s
go test ./pkg/parser/... -fuzz=FuzzParseSignatures -fuzztime=30s
```

## References

- [RFC 9421: HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)
- [RFC 8941: Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc8941.html)
- [RFC 9530: Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)

## License

MIT License - see [LICENSE](LICENSE) for details.
