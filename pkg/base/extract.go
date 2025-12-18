package base

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
)

// normalizeLineFolding replaces obsolete line folding with single space.
// RFC 9421 Section 2.1: obs-fold is CRLF or LF followed by one or more whitespace characters.
// This function replaces each sequence of (CRLF|LF) + whitespace with a single space.
func normalizeLineFolding(s string) string {
	// Fast path: no folding characters present (99% of cases)
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}

	// Slow path: build normalized string
	var result strings.Builder
	result.Grow(len(s))

	i := 0
	for i < len(s) {
		// Check for CRLF or LF followed by whitespace
		if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
			// Found CRLF
			if i+2 < len(s) && (s[i+2] == ' ' || s[i+2] == '\t') {
				// CRLF followed by whitespace - this is obs-fold
				// Skip CRLF and all following whitespace, replace with single space
				i += 2 // Skip \r\n
				for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
					i++
				}
				result.WriteByte(' ')
			} else {
				// CRLF not followed by whitespace - keep as is
				result.WriteByte('\r')
				i++
			}
		} else if s[i] == '\n' {
			// Found LF (without CR)
			if i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				// LF followed by whitespace - this is obs-fold
				// Skip LF and all following whitespace, replace with single space
				i++ // Skip \n
				for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
					i++
				}
				result.WriteByte(' ')
			} else {
				// LF not followed by whitespace - keep as is
				result.WriteByte('\n')
				i++
			}
		} else {
			// Regular character
			result.WriteByte(s[i])
			i++
		}
	}

	return result.String()
}

// extractComponentValue extracts the canonicalized value for a component identifier.
//
// RFC 9421 Section 2: Component values are extracted differently based on type:
// - HTTP fields (Section 2.1): Extracted from headers/trailers with comma-join for multiple values
// - Derived components (Section 2.2): Computed from HTTP message metadata (@method, @path, etc.)
//
// RFC 9421 Section 2.4: The 'req' parameter allows accessing request components from a response signature.
//
// Returns an error if:
// - The component is not found (missing header, invalid derived component for message type)
// - The component type is unknown or unsupported
// - A derived component is not valid for the message type (e.g., @status on request)
// - The 'req' parameter is used but no related request is available
func extractComponentValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	// Check for 'req' parameter - allows accessing request components from response signature
	hasReqParam := false
	for _, param := range comp.Parameters {
		if param.Key == "req" {
			if boolVal, ok := param.Value.(parser.Boolean); ok && boolVal.Value {
				hasReqParam = true
				break
			}
		}
	}

	// If 'req' parameter is present, extract from related request instead
	if hasReqParam {
		if !msg.IsResponse() {
			return "", fmt.Errorf("'req' parameter is only valid for response signatures")
		}

		relatedReq := msg.RelatedRequest()
		if relatedReq == nil {
			return "", fmt.Errorf("'req' parameter specified but no related request available")
		}

		// Remove 'req' parameter before extracting from request
		compForReq := parser.ComponentIdentifier{
			Name:       comp.Name,
			Type:       comp.Type,
			Parameters: make([]parser.Parameter, 0, len(comp.Parameters)-1),
		}
		for _, param := range comp.Parameters {
			if param.Key != "req" {
				compForReq.Parameters = append(compForReq.Parameters, param)
			}
		}

		return extractComponentValue(relatedReq, compForReq)
	}

	switch comp.Type {
	case parser.ComponentField:
		return extractHTTPFieldValue(msg, comp)
	case parser.ComponentDerived:
		return extractDerivedComponentValue(msg, comp)
	default:
		return "", fmt.Errorf("unknown component type: %v", comp.Type)
	}
}

// extractHTTPFieldValue extracts HTTP field values per RFC 9421 Section 2.1.
//
// RFC 9421 Section 2.1 Canonicalization Algorithm:
// 1. Create ordered list of field values in the order they occur
// 2. Strip leading and trailing whitespace from each value
// 3. Remove obsolete line folding (replace with single space)
// 4. Concatenate values with ", " (comma + space)
//
// Component Parameters (RFC 9421 Section 2.1):
//   - tr: Extract from trailers instead of headers
//   - sf: Serialize as RFC 8941 Structured Field (FR-011)
//   - bs: Encode as base64 byte sequence wrapped in :value: (FR-012)
//   - key: Extract specific dictionary member (FR-013)
func extractHTTPFieldValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	// Parse component parameters
	var isTrailer, useSF, useBS bool
	var keyName string

	for _, param := range comp.Parameters {
		switch param.Key {
		case "tr":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				isTrailer = boolVal.Value
			}
		case "sf":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				useSF = boolVal.Value
			}
		case "bs":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				useBS = boolVal.Value
			}
		case "key":
			if strVal, ok := param.Value.(parser.String); ok {
				keyName = strVal.Value
			}
		}
	}

	// RFC 9421 Section 2.1.1: Validate parameter combinations (FR-017, FR-018)
	if useSF && useBS {
		return "", fmt.Errorf("component %q: 'sf' and 'bs' parameters are mutually exclusive (RFC 9421 Section 2.1.1)", comp.Name)
	}
	if keyName != "" && !useSF {
		return "", fmt.Errorf("component %q: 'key' parameter requires 'sf' parameter for structured field dictionary (RFC 9421 Section 2.1.2)", comp.Name)
	}

	// Step 1: Extract field values in order
	var values []string
	if isTrailer {
		values = msg.TrailerValues(comp.Name)
	} else {
		values = msg.HeaderValues(comp.Name)
	}

	// RFC 9421: Missing header is an error
	if len(values) == 0 {
		fieldType := "header"
		if isTrailer {
			fieldType = "trailer"
		}
		return "", fmt.Errorf("%s field %q not found", fieldType, comp.Name)
	}

	// Step 2 & 3: Strip leading/trailing whitespace and normalize line folding
	normalizedValues := make([]string, len(values))
	for i, v := range values {
		// Step 3: Replace obsolete line folding with single space
		// RFC 9421 Section 2.1: obs-fold is CRLF or LF followed by whitespace
		// Replace the entire sequence (newline + all following whitespace) with single space
		v = normalizeLineFolding(v)

		// Step 2: Strip leading and trailing whitespace
		// Note: This must come AFTER line folding normalization to handle edge cases
		v = strings.TrimSpace(v)

		normalizedValues[i] = v
	}

	// Step 4: Join multiple values with ", " (comma + space)
	rawValue := strings.Join(normalizedValues, ", ")

	// Step 5: Apply parameter-specific processing

	// SF Parameter: Serialize as RFC 8941 Structured Field (FR-011)
	// This must be processed BEFORE the 'key' parameter if both are present
	if useSF {
		// Parse the raw value as a Structured Field
		// Try parsing as dictionary first, then as item
		sfvParser := sfv.NewParser(rawValue, sfv.DefaultLimits())

		// If key parameter is specified, we're extracting a dictionary member
		if keyName != "" {
			// Parse as dictionary (FR-013)
			dict, err := sfvParser.ParseDictionary()
			if err != nil {
				return "", fmt.Errorf("component %q: failed to parse as structured field dictionary: %w", comp.Name, err)
			}

			// Extract the specified member
			memberValue, exists := dict.Values[keyName]
			if !exists {
				return "", fmt.Errorf("component %q: dictionary member %q not found", comp.Name, keyName)
			}

			// Serialize the member value
			switch v := memberValue.(type) {
			case sfv.Item:
				serialized, err := sfv.SerializeItem(v)
				if err != nil {
					return "", fmt.Errorf("component %q: failed to serialize dictionary member %q: %w", comp.Name, keyName, err)
				}
				return serialized, nil

			case sfv.InnerList:
				serialized, err := sfv.SerializeInnerList(v)
				if err != nil {
					return "", fmt.Errorf("component %q: failed to serialize dictionary member %q: %w", comp.Name, keyName, err)
				}
				return serialized, nil

			default:
				return "", fmt.Errorf("component %q: invalid dictionary member type for %q: %T", comp.Name, keyName, memberValue)
			}
		}

		// No key parameter - serialize the entire field
		// Try dictionary first (most common for structured fields)
		dict, dictErr := sfvParser.ParseDictionary()
		if dictErr == nil {
			serialized, err := sfv.SerializeDictionary(dict)
			if err != nil {
				return "", fmt.Errorf("component %q: failed to serialize structured field dictionary: %w", comp.Name, err)
			}
			return serialized, nil
		}

		// Try parsing as item (single value)
		sfvParser = sfv.NewParser(rawValue, sfv.DefaultLimits())
		item, itemErr := sfvParser.ParseItem()
		if itemErr == nil {
			serialized, err := sfv.SerializeItem(*item)
			if err != nil {
				return "", fmt.Errorf("component %q: failed to serialize structured field item: %w", comp.Name, err)
			}
			return serialized, nil
		}

		// If both parsing attempts failed, return the dictionary error (more likely use case)
		//nolint:errorlint // Only one error can be wrapped per fmt.Errorf; wrapping itemErr as it's the last attempt
		return "", fmt.Errorf("component %q: failed to parse as structured field (dict error: %v, item error: %w)", comp.Name, dictErr, itemErr)
	}

	// BS Parameter: Base64-encode as byte sequence (FR-012)
	// RFC 9421 Section 2.1.3: Byte sequences are wrapped in colons :base64:
	if useBS {
		encoded := base64.StdEncoding.EncodeToString([]byte(rawValue))
		return ":" + encoded + ":", nil
	}

	// Default: Return raw canonicalized value (no special processing)
	return rawValue, nil
}

// extractDerivedComponentValue extracts derived components per RFC 9421 Section 2.2.
//
// RFC 9421 Section 2.2: Derived components start with @ and are computed from
// HTTP message metadata rather than being directly present in headers.
//
// Request-only derived components:
// - @method: HTTP method (GET, POST, etc.)
// - @target-uri: Complete request URI
// - @authority: Host and port from request URI
// - @scheme: URI scheme (http, https)
// - @request-target: Path and query from request URI
// - @path: Path component only
// - @query: Query string with leading ?
// - @query-param: Single query parameter value (requires name parameter)
//
// Response-only derived components:
// - @status: HTTP status code (200, 404, etc.)
//
// Both request and response:
// - None currently defined in RFC 9421
func extractDerivedComponentValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	switch comp.Name {
	case "@method":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@method is only valid for requests")
		}
		return msg.Method(), nil

	case "@target-uri":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@target-uri is only valid for requests")
		}
		url := msg.URL()
		return url.String(), nil

	case "@authority":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@authority is only valid for requests")
		}
		url := msg.URL()
		return url.Host, nil

	case "@scheme":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@scheme is only valid for requests")
		}
		url := msg.URL()
		return url.Scheme, nil

	case "@request-target":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@request-target is only valid for requests")
		}
		url := msg.URL()
		result := url.Path
		if url.RawQuery != "" {
			result += "?" + url.RawQuery
		}
		return result, nil

	case "@path":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@path is only valid for requests")
		}
		url := msg.URL()
		// RFC 9421 Section 2.2.6: an empty path string is normalized as a single slash (/) character
		if url.Path == "" {
			return "/", nil
		}
		return url.Path, nil

	case "@query":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@query is only valid for requests")
		}
		url := msg.URL()
		if url.RawQuery == "" {
			return "?", nil
		}
		return "?" + url.RawQuery, nil

	case "@query-param":
		if !msg.IsRequest() {
			return "", fmt.Errorf("@query-param is only valid for requests")
		}
		// RFC 9421 Section 2.2.8: Requires 'name' parameter
		var paramName string
		for _, param := range comp.Parameters {
			if param.Key == "name" {
				if strVal, ok := param.Value.(parser.String); ok {
					paramName = strVal.Value
					break
				}
			}
		}
		if paramName == "" {
			return "", fmt.Errorf("@query-param requires 'name' parameter")
		}

		url := msg.URL()
		values := url.Query()[paramName]
		if len(values) == 0 {
			return "", fmt.Errorf("query parameter %q not found", paramName)
		}
		// RFC 9421: Only returns first value if multiple exist
		return values[0], nil

	case "@status":
		if !msg.IsResponse() {
			return "", fmt.Errorf("@status is only valid for responses")
		}
		return strconv.Itoa(msg.StatusCode()), nil

	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.Name)
	}
}
