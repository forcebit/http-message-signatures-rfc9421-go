package base

import (
	"net/http"
	"testing"
)

func TestWrapRequest(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com:8080/path?query=value", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-Custom", "value1")
	req.Header.Add("X-Custom", "value2")

	wrapped := WrapRequest(req)

	t.Run("IsRequest returns true", func(t *testing.T) {
		if !wrapped.IsRequest() {
			t.Error("IsRequest() should return true for request wrapper")
		}
	})

	t.Run("IsResponse returns false", func(t *testing.T) {
		if wrapped.IsResponse() {
			t.Error("IsResponse() should return false for request wrapper")
		}
	})

	t.Run("Method returns HTTP method", func(t *testing.T) {
		if got := wrapped.Method(); got != "POST" {
			t.Errorf("Method() = %q, want %q", got, "POST")
		}
	})

	t.Run("URL returns request URL", func(t *testing.T) {
		got := wrapped.URL()
		if got.Scheme != "https" {
			t.Errorf("URL().Scheme = %q, want %q", got.Scheme, "https")
		}
		if got.Host != "example.com:8080" {
			t.Errorf("URL().Host = %q, want %q", got.Host, "example.com:8080")
		}
		if got.Path != "/path" {
			t.Errorf("URL().Path = %q, want %q", got.Path, "/path")
		}
		if got.RawQuery != "query=value" {
			t.Errorf("URL().RawQuery = %q, want %q", got.RawQuery, "query=value")
		}
	})

	t.Run("HeaderValues returns single value", func(t *testing.T) {
		got := wrapped.HeaderValues("content-type")
		want := []string{"application/json"}
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("HeaderValues(\"content-type\") = %v, want %v", got, want)
		}
	})

	t.Run("HeaderValues returns multiple values", func(t *testing.T) {
		got := wrapped.HeaderValues("x-custom")
		want := []string{"value1", "value2"}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("HeaderValues(\"x-custom\") = %v, want %v", got, want)
		}
	})

	t.Run("HeaderValues case-insensitive", func(t *testing.T) {
		got := wrapped.HeaderValues("CONTENT-TYPE")
		if len(got) != 1 || got[0] != "application/json" {
			t.Errorf("HeaderValues(\"CONTENT-TYPE\") should be case-insensitive, got %v", got)
		}
	})

	t.Run("HeaderValues returns empty for missing header", func(t *testing.T) {
		got := wrapped.HeaderValues("missing-header")
		if len(got) != 0 {
			t.Errorf("HeaderValues(\"missing-header\") = %v, want empty slice", got)
		}
	})

	t.Run("RelatedRequest returns nil", func(t *testing.T) {
		if got := wrapped.RelatedRequest(); got != nil {
			t.Error("RelatedRequest() should return nil for request wrapper")
		}
	})

	t.Run("StatusCode panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("StatusCode() should panic when called on request")
			}
		}()
		wrapped.StatusCode()
	})
}

func TestWrapResponse(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Custom":     []string{"value1", "value2"},
		},
		Trailer: http.Header{
			"X-Trailer": []string{"trailer-value"},
		},
	}

	t.Run("without related request", func(t *testing.T) {
		wrapped := WrapResponse(resp, nil)

		if !wrapped.IsResponse() {
			t.Error("IsResponse() should return true for response wrapper")
		}

		if wrapped.IsRequest() {
			t.Error("IsRequest() should return false for response wrapper")
		}

		if got := wrapped.StatusCode(); got != 200 {
			t.Errorf("StatusCode() = %d, want %d", got, 200)
		}

		if got := wrapped.RelatedRequest(); got != nil {
			t.Error("RelatedRequest() should return nil when no related request provided")
		}
	})

	t.Run("with related request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		wrapped := WrapResponse(resp, req)

		relatedReq := wrapped.RelatedRequest()
		if relatedReq == nil {
			t.Fatal("RelatedRequest() should return non-nil when related request provided")
		}

		if !relatedReq.IsRequest() {
			t.Error("RelatedRequest() should return a request message")
		}

		if got := relatedReq.Method(); got != "GET" {
			t.Errorf("RelatedRequest().Method() = %q, want %q", got, "GET")
		}
	})

	t.Run("HeaderValues works", func(t *testing.T) {
		wrapped := WrapResponse(resp, nil)
		got := wrapped.HeaderValues("content-type")
		want := []string{"application/json"}
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("HeaderValues(\"content-type\") = %v, want %v", got, want)
		}
	})

	t.Run("TrailerValues works", func(t *testing.T) {
		wrapped := WrapResponse(resp, nil)
		got := wrapped.TrailerValues("x-trailer")
		want := []string{"trailer-value"}
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("TrailerValues(\"x-trailer\") = %v, want %v", got, want)
		}
	})

	t.Run("Method panics", func(t *testing.T) {
		wrapped := WrapResponse(resp, nil)
		defer func() {
			if r := recover(); r == nil {
				t.Error("Method() should panic when called on response")
			}
		}()
		wrapped.Method()
	})

	t.Run("URL panics", func(t *testing.T) {
		wrapped := WrapResponse(resp, nil)
		defer func() {
			if r := recover(); r == nil {
				t.Error("URL() should panic when called on response")
			}
		}()
		wrapped.URL()
	})
}
