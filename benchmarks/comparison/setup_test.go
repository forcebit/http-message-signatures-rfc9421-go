package comparison

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/parser"
)

const (
	benchmarkCreatedMaxAge     = 5 * time.Minute
	benchmarkCreatedFutureSkew = time.Minute
)

// Shared test keys - generated once at init
var (
	testRSAPrivKey *rsa.PrivateKey
	testRSAPubKey  *rsa.PublicKey
	testECPrivKey  *ecdsa.PrivateKey
	testECPubKey   *ecdsa.PublicKey
	testHMACKey    []byte
)

func init() {
	var err error

	// Generate RSA 2048-bit key pair
	testRSAPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate RSA key: " + err.Error())
	}
	testRSAPubKey = &testRSAPrivKey.PublicKey

	// Generate ECDSA P-256 key pair
	testECPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate ECDSA key: " + err.Error())
	}
	testECPubKey = &testECPrivKey.PublicKey

	// Generate HMAC key (64 bytes - required by yaronf/httpsign)
	testHMACKey = make([]byte, 64)
	if _, err = rand.Read(testHMACKey); err != nil {
		panic("failed to generate HMAC key: " + err.Error())
	}
}

// createTestRequest creates a standard HTTP request for benchmarking
func createTestRequest() *http.Request {
	body := `{"message": "hello world", "timestamp": 1234567890}`
	req := httptest.NewRequest(
		http.MethodPost,
		"https://example.com/api/resource?param=value",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "52")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	req.Host = "example.com"
	return req
}

// Components to sign for Forcebit
var testComponents = []parser.ComponentIdentifier{
	{Name: "@method", Type: parser.ComponentDerived},
	{Name: "@target-uri", Type: parser.ComponentDerived},
	{Name: "content-type", Type: parser.ComponentField},
}

func benchmarkValidationOptions() parser.SignatureParamsValidationOptions {
	return parser.SignatureParamsValidationOptions{
		RequireCreated:          true,
		CreatedNotOlderThan:     benchmarkCreatedMaxAge,
		CreatedNotNewerThan:     benchmarkCreatedFutureSkew,
		RejectExpired:           true,
		ExpiresNotBeforeCreated: true,
	}
}
