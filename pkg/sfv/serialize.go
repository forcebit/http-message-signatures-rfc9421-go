package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// SerializeItem serializes an RFC 8941 Item to its canonical string representation.
// Format: bare-item[;param1=value1;param2=value2...]
func SerializeItem(item Item) (string, error) {
	var sb strings.Builder

	// Serialize bare item value
	bareItem, err := serializeBareItem(item.Value)
	if err != nil {
		return "", err
	}
	sb.WriteString(bareItem)

	// Serialize parameters
	if len(item.Parameters) > 0 {
		params, err := serializeParameters(item.Parameters)
		if err != nil {
			return "", err
		}
		sb.WriteString(params)
	}

	return sb.String(), nil
}

// SerializeInnerList serializes an RFC 8941 InnerList to its canonical string representation.
// Format: (item1 item2 ...)[;param1=value1;param2=value2...]
func SerializeInnerList(innerList InnerList) (string, error) {
	var sb strings.Builder

	sb.WriteRune('(')

	// Serialize items
	for i, item := range innerList.Items {
		if i > 0 {
			sb.WriteRune(' ')
		}

		itemStr, err := SerializeItem(item)
		if err != nil {
			return "", err
		}
		sb.WriteString(itemStr)
	}

	sb.WriteRune(')')

	// Serialize parameters
	if len(innerList.Parameters) > 0 {
		params, err := serializeParameters(innerList.Parameters)
		if err != nil {
			return "", err
		}
		sb.WriteString(params)
	}

	return sb.String(), nil
}

// SerializeDictionary serializes an RFC 8941 Dictionary to its canonical string representation.
// Format: key1=value1, key2=value2, ...
func SerializeDictionary(dict *Dictionary) (string, error) {
	if len(dict.Keys) == 0 {
		return "", nil
	}

	var sb strings.Builder

	for i, key := range dict.Keys {
		if i > 0 {
			sb.WriteString(", ")
		}

		// Write key
		sb.WriteString(key)

		value := dict.Values[key]

		// Check if value is boolean true (bare key)
		if item, ok := value.(Item); ok {
			if boolVal, isBool := item.Value.(bool); isBool && boolVal && len(item.Parameters) == 0 {
				// Bare key (boolean true with no parameters)
				continue
			}
		}

		// Write '=' and value
		sb.WriteRune('=')

		switch v := value.(type) {
		case Item:
			itemStr, err := SerializeItem(v)
			if err != nil {
				return "", err
			}
			sb.WriteString(itemStr)

		case InnerList:
			innerListStr, err := SerializeInnerList(v)
			if err != nil {
				return "", err
			}
			sb.WriteString(innerListStr)

		default:
			return "", fmt.Errorf("invalid dictionary value type: %T", value)
		}
	}

	return sb.String(), nil
}

// SerializeList serializes an RFC 8941 List to its canonical string representation.
// Format: member1, member2, ...
func SerializeList(list *List) (string, error) {
	if len(list.Members) == 0 {
		return "", nil
	}

	var sb strings.Builder

	for i, member := range list.Members {
		if i > 0 {
			sb.WriteString(", ")
		}

		switch v := member.(type) {
		case Item:
			itemStr, err := SerializeItem(v)
			if err != nil {
				return "", err
			}
			sb.WriteString(itemStr)

		case InnerList:
			innerListStr, err := SerializeInnerList(v)
			if err != nil {
				return "", err
			}
			sb.WriteString(innerListStr)

		default:
			return "", fmt.Errorf("invalid list member type: %T", member)
		}
	}

	return sb.String(), nil
}

// serializeBareItem serializes a bare item value to its canonical string representation.
func serializeBareItem(value interface{}) (string, error) {
	switch v := value.(type) {
	case bool:
		// Boolean: ?0 or ?1
		if v {
			return "?1", nil
		}
		return "?0", nil

	case int64:
		// Integer: decimal representation
		return strconv.FormatInt(v, 10), nil

	case int:
		// Integer: decimal representation
		return strconv.Itoa(v), nil

	case string:
		// Check if this is a valid token (unquoted identifier)
		// RFC 8941: Tokens start with alpha or * and contain alphanumeric, *, _, -, ., :, /, or %
		if isValidToken(v) {
			// Serialize as token (unquoted)
			return v, nil
		}
		// Otherwise, serialize as quoted string with escape sequences
		return SerializeString(v), nil

	case []byte:
		// Byte sequence: :base64:
		encoded := base64.StdEncoding.EncodeToString(v)
		return ":" + encoded + ":", nil

	default:
		// Assume it's a token (string-like)
		if str, ok := v.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("unsupported bare item type: %T", value)
	}
}

// SerializeString serializes a string to RFC 8941 quoted string format.
// It escapes backslashes and double quotes per RFC 8941 Section 3.3.3.
func SerializeString(s string) string {
	var sb strings.Builder
	sb.WriteRune('"')

	for _, r := range s {
		if r == '\\' || r == '"' {
			sb.WriteRune('\\')
		}
		sb.WriteRune(r)
	}

	sb.WriteRune('"')
	return sb.String()
}

// serializeParameters serializes RFC 8941 parameters.
// Format: ;param1=value1;param2=value2...
func serializeParameters(params []Parameter) (string, error) {
	var sb strings.Builder

	for _, param := range params {
		sb.WriteRune(';')
		sb.WriteString(param.Key)

		// Boolean true parameters can be bare
		if boolVal, ok := param.Value.(bool); ok && boolVal {
			// Bare parameter (boolean true)
			continue
		}

		// Non-true values need '=' and value
		sb.WriteRune('=')

		bareItem, err := serializeBareItem(param.Value)
		if err != nil {
			return "", err
		}
		sb.WriteString(bareItem)
	}

	return sb.String(), nil
}

// isValidToken checks if a string is a valid RFC 8941 token.
// RFC 8941 Section 3.3.4: Tokens start with alpha or * and contain alphanumeric, *, _, -, ., :, /, or %
func isValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}

	// First character must be alpha or *
	first := rune(s[0])
	if !unicode.IsLetter(first) && first != '*' {
		return false
	}

	// Remaining characters must be alphanumeric or one of: * _ - . : / %
	for _, r := range s[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			r != '*' && r != '_' && r != '-' && r != '.' &&
			r != ':' && r != '/' && r != '%' {
			return false
		}
	}

	return true
}
