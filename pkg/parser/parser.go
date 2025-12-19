package parser

import (
	"fmt"

	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
)

// ParseSignatures parses RFC 9421 Signature-Input and Signature headers.
// Per Contract PS-001: Accepts RFC 8941 Dictionary format for both parameters.
// Per Contract PS-006: Returns descriptive errors, fails fast on validation errors.
// Per Contract PS-008: Thread-safe (stateless function).
//
// The limits parameter controls parser size limits for DoS prevention.
// Use sfv.DefaultLimits() for production, sfv.NoLimits() for trusted input.
//
// Example:
//
//	signatureInput := `sig1=("@method" "@path");alg="rsa-pss-sha512"`
//	signature := `sig1=:base64bytes:`
//	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
func ParseSignatures(signatureInput, signature string, limits sfv.Limits) (*ParsedSignatures, error) {
	// FR-020: Return error for empty headers
	if signatureInput == "" && signature == "" {
		return nil, fmt.Errorf("both Signature-Input and Signature headers are empty")
	}
	if signatureInput == "" {
		return nil, fmt.Errorf("header Signature-Input is empty")
	}
	if signature == "" {
		return nil, fmt.Errorf("header Signature is empty")
	}

	// T040: Parse Signature-Input header as RFC 8941 Dictionary
	inputParser := sfv.NewParser(signatureInput, limits)
	inputDict, err := inputParser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input header: %w", err)
	}

	// T041: Parse Signature header as RFC 8941 Dictionary
	sigParser := sfv.NewParser(signature, limits)
	sigDict, err := sigParser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature header: %w", err)
	}

	// T042: Extract signature labels and validate label correspondence (FR-007, FR-008)
	// Contract PS-002: Every label in signatureInput must have entry in signature
	for _, label := range inputDict.Keys {
		if _, exists := sigDict.Values[label]; !exists {
			return nil, fmt.Errorf("header Signature-Input label %q has no corresponding Signature entry", label)
		}
	}

	// Contract PS-002: Every label in signature must have entry in signatureInput
	for _, label := range sigDict.Keys {
		if _, exists := inputDict.Values[label]; !exists {
			return nil, fmt.Errorf("header Signature label %q has no corresponding Signature-Input entry", label)
		}
	}

	result := &ParsedSignatures{
		Signatures: make(map[string]SignatureEntry),
	}

	// Process each signature label
	for _, label := range inputDict.Keys {
		entry, err := parseSignatureEntry(label, inputDict.Values[label], sigDict.Values[label])
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature %q: %w", label, err)
		}
		result.Signatures[label] = entry
	}

	return result, nil
}

// parseSignatureEntry processes a single signature entry.
func parseSignatureEntry(label string, inputValue, sigValue interface{}) (SignatureEntry, error) {
	entry := SignatureEntry{
		Label: label,
	}

	// T043: Extract covered components list from inner list (FR-002)
	inputInnerList, ok := inputValue.(sfv.InnerList)
	if !ok {
		return entry, fmt.Errorf("header Signature-Input value must be an inner list")
	}

	// T043, T044: Extract covered components and their parameters
	entry.CoveredComponents = make([]ComponentIdentifier, len(inputInnerList.Items))
	for i, item := range inputInnerList.Items {
		compName, ok := item.Value.(string)
		if !ok {
			return entry, fmt.Errorf("covered component must be a string, got %T", item.Value)
		}

		// Determine component type (FR-003, FR-013, FR-014)
		// Per VR-009, VR-010: Name starting with "@" indicates derived component
		compType := ComponentField
		if len(compName) > 0 && compName[0] == '@' {
			compType = ComponentDerived
		}

		// T044: Extract component parameters (FR-004)
		params := make([]Parameter, len(item.Parameters))
		for j, sfvParam := range item.Parameters {
			params[j] = Parameter{
				Key:   sfvParam.Key,
				Value: convertBareItem(sfvParam.Value),
			}
		}

		entry.CoveredComponents[i] = ComponentIdentifier{
			Name:       compName,
			Type:       compType,
			Parameters: params,
		}

		// Validate component identifier (derived component whitelist, parameter combinations)
		if err := validateComponentIdentifier(entry.CoveredComponents[i]); err != nil {
			return entry, fmt.Errorf("invalid component at position %d: %w", i, err)
		}
	}

	// FR-002: At least one covered component recommended (but RFC allows empty for testing)
	// Note: RFC 9421 B.2.1 shows an example with empty component list, so we allow it
	// though it's discouraged in Section 7.2.1

	// T045: Extract signature parameters from inner list parameters (FR-005)
	var err error
	entry.SignatureParams, err = extractSignatureParams(inputInnerList.Parameters)
	if err != nil {
		return entry, err
	}

	// T046: Decode signature value byte sequence (FR-006)
	sigItem, ok := sigValue.(sfv.Item)
	if !ok {
		return entry, fmt.Errorf("signature value must be an item")
	}

	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		return entry, fmt.Errorf("signature value must be a byte sequence, got %T", sigItem.Value)
	}

	entry.SignatureValue = sigBytes

	return entry, nil
}

// extractSignatureParams extracts signature metadata parameters.
// Returns an error if a known parameter has an incorrect type per RFC 9421 Section 2.3.
// Unknown parameters are ignored to allow for future extensibility.
func extractSignatureParams(params []sfv.Parameter) (SignatureParams, error) {
	sp := SignatureParams{}

	for _, param := range params {
		switch param.Key {
		case "created":
			val, ok := param.Value.(int64)
			if !ok {
				return sp, fmt.Errorf("parameter 'created' must be an integer, got %T", param.Value)
			}
			sp.Created = &val
		case "expires":
			val, ok := param.Value.(int64)
			if !ok {
				return sp, fmt.Errorf("parameter 'expires' must be an integer, got %T", param.Value)
			}
			sp.Expires = &val
		case "nonce":
			val, ok := param.Value.(string)
			if !ok {
				return sp, fmt.Errorf("parameter 'nonce' must be a string, got %T", param.Value)
			}
			sp.Nonce = &val
		case "alg":
			val, ok := param.Value.(string)
			if !ok {
				return sp, fmt.Errorf("parameter 'alg' must be a string, got %T", param.Value)
			}
			sp.Algorithm = &val
		case "keyid":
			val, ok := param.Value.(string)
			if !ok {
				return sp, fmt.Errorf("parameter 'keyid' must be a string, got %T", param.Value)
			}
			sp.KeyID = &val
		case "tag":
			val, ok := param.Value.(string)
			if !ok {
				return sp, fmt.Errorf("parameter 'tag' must be a string, got %T", param.Value)
			}
			sp.Tag = &val
			// Unknown parameters are ignored per RFC 9421 (extensibility)
		}
	}

	// Algorithm is RECOMMENDED per RFC 9421 Section 2.3, but not strictly required
	// The RFC 9421 Appendix B test cases don't include 'alg', so we allow it to be empty
	// Note: Verifiers should reject signatures without 'alg' in production use

	return sp, nil
}

// convertBareItem converts SFV bare item to parser BareItem interface.
func convertBareItem(value interface{}) BareItem {
	switch v := value.(type) {
	case bool:
		return Boolean{Value: v}
	case int64:
		return Integer{Value: v}
	case sfv.Token:
		// Token: unquoted identifier (preserved from parsing)
		return Token{Value: v.Value}
	case string:
		// String: quoted string value
		return String{Value: v}
	case []byte:
		return ByteSequence{Value: v}
	default:
		// Fallback: treat as string representation
		return String{Value: fmt.Sprint(v)}
	}
}
