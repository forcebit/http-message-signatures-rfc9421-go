package comparison

import (
	"context"
	"crypto"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Forcebit
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/base"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/signing"

	// yaronf/httpsign
	yaronf "github.com/yaronf/httpsign"

	// remitly-oss/httpsig-go
	remitly "github.com/remitly-oss/httpsig-go"

	// common-fate/httpsig
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/alg_hmac"
	"github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/sigset"
	"github.com/common-fate/httpsig/verifier"
)

// =============================================================================
// RSA-PSS-SHA512 Sign Benchmarks
// =============================================================================

func BenchmarkSign_RSAPSS_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
	params := testSignatureParams("test-key-rsa", "rsa-pss-sha512")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg := base.WrapRequest(req)
		sigBase, _ := base.Build(msg, testComponents, params)
		_, _ = alg.Sign([]byte(sigBase), testRSAPrivKey)
	}
}

func BenchmarkSign_RSAPSS_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-rsa").SignAlg(false)

	signerY, err := yaronf.NewRSAPSSSigner(*testRSAPrivKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_RSAPSS_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_RSA_PSS_SHA512,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Key:       testRSAPrivKey,
		MetaKeyID: "test-key-rsa",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_RSAPSS_CommonFate(b *testing.B) {
	sigAlg := alg_rsa.NewRSAPSS512Signer(testRSAPrivKey)
	transport := &signer.Transport{
		KeyID: "test-key-rsa",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// RSA-PSS-SHA512 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_RSAPSS_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
	params := testSignatureParams("test-key-rsa", "rsa-pss-sha512")

	// Pre-sign for verification
	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, _ := base.Build(msg, testComponents, params)
	sig, _ := alg.Sign([]byte(sigBase), testRSAPrivKey)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify([]byte(sigBase), sig, testRSAPubKey)
	}
}

func BenchmarkVerify_RSAPSS_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-rsa").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().SetKeyID("test-key-rsa").SetVerifyCreated(false)

	signerY, _ := yaronf.NewRSAPSSSigner(*testRSAPrivKey, signConfig, fields)
	verifierY, _ := yaronf.NewRSAPSSVerifier(*testRSAPubKey, verifyConfig, fields)

	// Pre-sign request
	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_RSAPSS_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_RSA_PSS_SHA512,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Key:       testRSAPrivKey,
		MetaKeyID: "test-key-rsa",
	}

	// Pre-sign request
	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	// Create verifier with correct label
	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:    "sig1",
		AllowedAlgorithms: []remitly.Algorithm{remitly.Algo_RSA_PSS_SHA512},
	}
	kf := &remitlyStaticKeyFetcher{
		keyID:  "test-key-rsa",
		algo:   remitly.Algo_RSA_PSS_SHA512,
		pubKey: testRSAPubKey,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_RSAPSS_CommonFate(b *testing.B) {
	sigAlg := alg_rsa.NewRSAPSS512Signer(testRSAPrivKey)
	transport := &signer.Transport{
		KeyID: "test-key-rsa",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	// Pre-sign request and add signature headers
	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := &commonFateRSAKeyDir{
		verifier: alg_rsa.NewRSAPSS512Verifier(testRSAPubKey),
	}

	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: 5 * time.Second, // Allow 5 second clock skew
		},
	}

	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, now)
	}
}

// =============================================================================
// ECDSA-P256-SHA256 Sign Benchmarks
// =============================================================================

func BenchmarkSign_ECDSA_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("ecdsa-p256-sha256")
	params := testSignatureParams("test-key-ecdsa", "ecdsa-p256-sha256")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg := base.WrapRequest(req)
		sigBase, _ := base.Build(msg, testComponents, params)
		_, _ = alg.Sign([]byte(sigBase), testECPrivKey)
	}
}

func BenchmarkSign_ECDSA_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-ecdsa").SignAlg(false)

	signerY, err := yaronf.NewP256Signer(*testECPrivKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_ECDSA_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_ECDSA_P256_SHA256,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Key:       testECPrivKey,
		MetaKeyID: "test-key-ecdsa",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_ECDSA_CommonFate(b *testing.B) {
	sigAlg := alg_ecdsa.NewP256Signer(testECPrivKey)
	transport := &signer.Transport{
		KeyID: "test-key-ecdsa",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// ECDSA-P256-SHA256 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_ECDSA_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("ecdsa-p256-sha256")
	params := testSignatureParams("test-key-ecdsa", "ecdsa-p256-sha256")

	// Pre-sign for verification
	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, _ := base.Build(msg, testComponents, params)
	sig, _ := alg.Sign([]byte(sigBase), testECPrivKey)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify([]byte(sigBase), sig, testECPubKey)
	}
}

func BenchmarkVerify_ECDSA_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-ecdsa").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().SetKeyID("test-key-ecdsa").SetVerifyCreated(false)

	signerY, _ := yaronf.NewP256Signer(*testECPrivKey, signConfig, fields)
	verifierY, _ := yaronf.NewP256Verifier(*testECPubKey, verifyConfig, fields)

	// Pre-sign request
	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_ECDSA_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_ECDSA_P256_SHA256,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Key:       testECPrivKey,
		MetaKeyID: "test-key-ecdsa",
	}

	// Pre-sign request
	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	// Create verifier with correct label
	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:    "sig1",
		AllowedAlgorithms: []remitly.Algorithm{remitly.Algo_ECDSA_P256_SHA256},
	}
	kf := &remitlyStaticKeyFetcher{
		keyID:  "test-key-ecdsa",
		algo:   remitly.Algo_ECDSA_P256_SHA256,
		pubKey: testECPubKey,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_ECDSA_CommonFate(b *testing.B) {
	sigAlg := alg_ecdsa.NewP256Signer(testECPrivKey)
	transport := &signer.Transport{
		KeyID: "test-key-ecdsa",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	// Pre-sign request and add signature headers
	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := &commonFateECDSAKeyDir{
		verifier: alg_ecdsa.NewP256Verifier(testECPubKey),
	}

	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: 5 * time.Second, // Allow 5 second clock skew
		},
	}

	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, now)
	}
}

// =============================================================================
// HMAC-SHA256 Sign Benchmarks
// =============================================================================

func BenchmarkSign_HMAC_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("hmac-sha256")
	params := testSignatureParams("test-key-hmac", "hmac-sha256")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg := base.WrapRequest(req)
		sigBase, _ := base.Build(msg, testComponents, params)
		_, _ = alg.Sign([]byte(sigBase), testHMACKey)
	}
}

func BenchmarkSign_HMAC_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-hmac").SignAlg(false)

	signerY, err := yaronf.NewHMACSHA256Signer(testHMACKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_HMAC_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_HMAC_SHA256,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Secret:    testHMACKey,
		MetaKeyID: "test-key-hmac",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_HMAC_CommonFate(b *testing.B) {
	sigAlg := alg_hmac.NewHMAC(testHMACKey)
	transport := &signer.Transport{
		KeyID: "test-key-hmac",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// HMAC-SHA256 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_HMAC_Forcebit(b *testing.B) {
	alg, _ := signing.GetAlgorithm("hmac-sha256")
	params := testSignatureParams("test-key-hmac", "hmac-sha256")

	// Pre-sign for verification
	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, _ := base.Build(msg, testComponents, params)
	sig, _ := alg.Sign([]byte(sigBase), testHMACKey)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify([]byte(sigBase), sig, testHMACKey)
	}
}

func BenchmarkVerify_HMAC_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@authority", "@path", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-hmac").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().SetKeyID("test-key-hmac").SetVerifyCreated(false)

	signerY, _ := yaronf.NewHMACSHA256Signer(testHMACKey, signConfig, fields)
	verifierY, _ := yaronf.NewHMACSHA256Verifier(testHMACKey, verifyConfig, fields)

	// Pre-sign request
	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_HMAC_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_HMAC_SHA256,
		Fields:    remitly.Fields("@method", "@authority", "@path", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{
		Secret:    testHMACKey,
		MetaKeyID: "test-key-hmac",
	}

	// Pre-sign request
	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	// Create verifier with correct label
	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:    "sig1",
		AllowedAlgorithms: []remitly.Algorithm{remitly.Algo_HMAC_SHA256},
	}
	kf := &remitlyStaticKeyFetcher{
		keyID:  "test-key-hmac",
		algo:   remitly.Algo_HMAC_SHA256,
		secret: testHMACKey,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_HMAC_CommonFate(b *testing.B) {
	sigAlg := alg_hmac.NewHMAC(testHMACKey)
	transport := &signer.Transport{
		KeyID: "test-key-hmac",
		Tag:   "benchmark",
		Alg:   sigAlg,
		CoveredComponents: []string{
			"@method", "@target-uri", "content-type",
		},
	}

	// Pre-sign request and add signature headers
	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := alg_hmac.NewSingleHMACKeyDirectory(alg_hmac.NewHMAC(testHMACKey))

	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: 5 * time.Second, // Allow 5 second clock skew
		},
	}

	now := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, now)
	}
}

// =============================================================================
// Helper types for library adapters
// =============================================================================

// remitlyStaticKeyFetcher implements remitly's KeyFetcher interface
type remitlyStaticKeyFetcher struct {
	keyID  string
	algo   remitly.Algorithm
	pubKey crypto.PublicKey
	secret []byte
}

func (f *remitlyStaticKeyFetcher) FetchByKeyID(_ context.Context, _ http.Header, _ string) (remitly.KeySpecer, error) {
	if f.secret != nil {
		return remitly.KeySpec{
			KeyID:  f.keyID,
			Algo:   f.algo,
			Secret: f.secret,
		}, nil
	}
	return remitly.KeySpec{
		KeyID:  f.keyID,
		Algo:   f.algo,
		PubKey: f.pubKey,
	}, nil
}

func (f *remitlyStaticKeyFetcher) Fetch(ctx context.Context, rh http.Header, _ remitly.MetadataProvider) (remitly.KeySpecer, error) {
	return f.FetchByKeyID(ctx, rh, f.keyID)
}

// commonFateRSAKeyDir implements common-fate's KeyDirectory interface for RSA
type commonFateRSAKeyDir struct {
	verifier *alg_rsa.RSAPSS512
}

func (d *commonFateRSAKeyDir) GetKey(_ context.Context, _ string, _ string) (verifier.Algorithm, error) {
	return d.verifier, nil
}

// commonFateECDSAKeyDir implements common-fate's KeyDirectory interface for ECDSA
type commonFateECDSAKeyDir struct {
	verifier *alg_ecdsa.P256
}

func (d *commonFateECDSAKeyDir) GetKey(_ context.Context, _ string, _ string) (verifier.Algorithm, error) {
	return d.verifier, nil
}

// noopNonceStorage implements common-fate's NonceStorage interface (no-op for benchmarks)
type noopNonceStorage struct{}

func (n *noopNonceStorage) Seen(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// =============================================================================
// Comparison Benchmarks (grouped by algorithm)
// =============================================================================

func BenchmarkSign_AllLibraries_RSAPSS(b *testing.B) {
	b.Run("Forcebit", BenchmarkSign_RSAPSS_Forcebit)
	b.Run("Yaronf", BenchmarkSign_RSAPSS_Yaronf)
	b.Run("Remitly", BenchmarkSign_RSAPSS_Remitly)
	b.Run("CommonFate", BenchmarkSign_RSAPSS_CommonFate)
}

func BenchmarkSign_AllLibraries_ECDSA(b *testing.B) {
	b.Run("Forcebit", BenchmarkSign_ECDSA_Forcebit)
	b.Run("Yaronf", BenchmarkSign_ECDSA_Yaronf)
	b.Run("Remitly", BenchmarkSign_ECDSA_Remitly)
	b.Run("CommonFate", BenchmarkSign_ECDSA_CommonFate)
}

func BenchmarkSign_AllLibraries_HMAC(b *testing.B) {
	b.Run("Forcebit", BenchmarkSign_HMAC_Forcebit)
	b.Run("Yaronf", BenchmarkSign_HMAC_Yaronf)
	b.Run("Remitly", BenchmarkSign_HMAC_Remitly)
	b.Run("CommonFate", BenchmarkSign_HMAC_CommonFate)
}

func BenchmarkVerify_AllLibraries_RSAPSS(b *testing.B) {
	b.Run("Forcebit", BenchmarkVerify_RSAPSS_Forcebit)
	b.Run("Yaronf", BenchmarkVerify_RSAPSS_Yaronf)
	b.Run("Remitly", BenchmarkVerify_RSAPSS_Remitly)
	b.Run("CommonFate", BenchmarkVerify_RSAPSS_CommonFate)
}

func BenchmarkVerify_AllLibraries_ECDSA(b *testing.B) {
	b.Run("Forcebit", BenchmarkVerify_ECDSA_Forcebit)
	b.Run("Yaronf", BenchmarkVerify_ECDSA_Yaronf)
	b.Run("Remitly", BenchmarkVerify_ECDSA_Remitly)
	b.Run("CommonFate", BenchmarkVerify_ECDSA_CommonFate)
}

func BenchmarkVerify_AllLibraries_HMAC(b *testing.B) {
	b.Run("Forcebit", BenchmarkVerify_HMAC_Forcebit)
	b.Run("Yaronf", BenchmarkVerify_HMAC_Yaronf)
	b.Run("Remitly", BenchmarkVerify_HMAC_Remitly)
	b.Run("CommonFate", BenchmarkVerify_HMAC_CommonFate)
}

// =============================================================================
// Sanity Tests (ensure signing and verification work)
// =============================================================================

func TestSign_RSAPSS_Forcebit(t *testing.T) {
	alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
	params := testSignatureParams("test-key-rsa", "rsa-pss-sha512")

	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, err := base.Build(msg, testComponents, params)
	if err != nil {
		t.Fatalf("failed to build signature base: %v", err)
	}

	sig, err := alg.Sign([]byte(sigBase), testRSAPrivKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if err := alg.Verify([]byte(sigBase), sig, testRSAPubKey); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("RSA-PSS signature: %s", base64.StdEncoding.EncodeToString(sig))
}

func TestSign_ECDSA_Forcebit(t *testing.T) {
	alg, _ := signing.GetAlgorithm("ecdsa-p256-sha256")
	params := testSignatureParams("test-key-ecdsa", "ecdsa-p256-sha256")

	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, err := base.Build(msg, testComponents, params)
	if err != nil {
		t.Fatalf("failed to build signature base: %v", err)
	}

	sig, err := alg.Sign([]byte(sigBase), testECPrivKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if err := alg.Verify([]byte(sigBase), sig, testECPubKey); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("ECDSA signature: %s", base64.StdEncoding.EncodeToString(sig))
}

func TestSign_HMAC_Forcebit(t *testing.T) {
	alg, _ := signing.GetAlgorithm("hmac-sha256")
	params := testSignatureParams("test-key-hmac", "hmac-sha256")

	req := createTestRequest()
	msg := base.WrapRequest(req)
	sigBase, err := base.Build(msg, testComponents, params)
	if err != nil {
		t.Fatalf("failed to build signature base: %v", err)
	}

	sig, err := alg.Sign([]byte(sigBase), testHMACKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if err := alg.Verify([]byte(sigBase), sig, testHMACKey); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("HMAC signature: %s", base64.StdEncoding.EncodeToString(sig))
}
