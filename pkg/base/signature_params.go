package base

import (
	"fmt"
	"strings"

	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/parser"
)

// formatSignatureParamsLine constructs the @signature-params line per RFC 9421 Section 2.5.
//
// The @signature-params line contains:
// 1. The covered component identifiers as an inner list
// 2. The signature metadata parameters (created, expires, nonce, alg, keyid, tag)
//
// Format: "@signature-params": (component-identifiers);param1=value1;param2=value2
//
// RFC 9421 Section 2.3: All signature parameters are optional.
// RFC 9421 Section 2.5: Parameters must appear in canonical order.
func formatSignatureParamsLine(components []parser.ComponentIdentifier, params parser.SignatureParams) string {
	var sb strings.Builder

	// Start with the component name
	sb.WriteString(`"@signature-params": (`)

	// Add component identifiers
	for i, comp := range components {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(formatComponentIdentifier(comp))
	}

	sb.WriteString(")")

	// Add signature metadata parameters in canonical order
	// RFC 9421 Section 2.3 defines the order: created, expires, nonce, alg, keyid, tag
	if params.Created != nil {
		sb.WriteString(fmt.Sprintf(";created=%d", *params.Created))
	}
	if params.Expires != nil {
		sb.WriteString(fmt.Sprintf(";expires=%d", *params.Expires))
	}
	if params.Nonce != nil {
		sb.WriteString(fmt.Sprintf(`;nonce="%s"`, *params.Nonce))
	}
	if params.Algorithm != nil {
		sb.WriteString(fmt.Sprintf(`;alg="%s"`, *params.Algorithm))
	}
	if params.KeyID != nil {
		sb.WriteString(fmt.Sprintf(`;keyid="%s"`, *params.KeyID))
	}
	if params.Tag != nil {
		sb.WriteString(fmt.Sprintf(`;tag="%s"`, *params.Tag))
	}

	return sb.String()
}

// formatComponentIdentifier formats a component identifier with its parameters.
//
// Format: "component-name" or "component-name";param1;param2=value
//
// Component parameters (RFC 9421 Section 2.1):
// - sf: boolean (Structured Field serialization)
// - bs: boolean (Byte Sequence encoding)
// - key: string (dictionary member key)
// - req: boolean (request component from response signature)
// - tr: boolean (trailer field)
// - name: string (query parameter name for @query-param)
//
// Parameters are serialized in the order they appear in the Parameters slice.
func formatComponentIdentifier(comp parser.ComponentIdentifier) string {
	var sb strings.Builder

	// Component name is always quoted
	sb.WriteString(`"`)
	sb.WriteString(comp.Name)
	sb.WriteString(`"`)

	// Add component parameters in the order they appear
	for _, param := range comp.Parameters {
		sb.WriteString(";")
		sb.WriteString(param.Key)

		// Boolean true parameters appear as flags (no value)
		if boolVal, ok := param.Value.(parser.Boolean); ok {
			if !boolVal.Value {
				// Boolean false is represented with =?0
				sb.WriteString("=?0")
			}
			// Boolean true is just the flag name (no =?1)
			continue
		}

		// String parameters appear as key="value"
		if strVal, ok := param.Value.(parser.String); ok {
			sb.WriteString(`="`)
			sb.WriteString(strVal.Value)
			sb.WriteString(`"`)
			continue
		}

		// Token parameters appear as key=token (no quotes)
		if tokVal, ok := param.Value.(parser.Token); ok {
			sb.WriteString("=")
			sb.WriteString(tokVal.Value)
			continue
		}

		// Integer parameters appear as key=123
		if intVal, ok := param.Value.(parser.Integer); ok {
			sb.WriteString(fmt.Sprintf("=%d", intVal.Value))
			continue
		}

		// ByteSequence parameters appear as key=:base64:
		if bsVal, ok := param.Value.(parser.ByteSequence); ok {
			sb.WriteString("=:")
			sb.WriteString(string(bsVal.Value)) // Already base64 encoded
			sb.WriteString(":")
		}
	}

	return sb.String()
}
