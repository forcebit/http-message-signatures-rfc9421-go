// Package base provides signature base construction per RFC 9421.
package base

import (
	"errors"
	"net/http"
	"net/url"
)

// requestWrapper adapts *http.Request to the HTTPMessage interface.
type requestWrapper struct {
	req       *http.Request
	cachedURL *url.URL
}

// WrapRequest adapts a standard *http.Request to the HTTPMessage interface.
//
// This enables signature base construction for HTTP requests using Go's
// standard library types.
//
// Example:
//
//	req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
//	req.Header.Set("Content-Type", "application/json")
//
//	message := base.WrapRequest(req)
//	signatureBase, err := base.Build(message, components, params)
func WrapRequest(req *http.Request) HTTPMessage {
	return &requestWrapper{req: req}
}

func (w *requestWrapper) IsRequest() bool {
	return true
}

func (w *requestWrapper) IsResponse() bool {
	return false
}

func (w *requestWrapper) Method() (string, error) {
	return w.req.Method, nil
}

func (w *requestWrapper) URL() (*url.URL, error) {
	if w.cachedURL != nil {
		return w.cachedURL, nil
	}

	u := w.req.URL

	// For server-side requests, URL.Scheme and URL.Host are empty.
	// Reconstruct from req.Host and req.TLS.
	if u.Scheme == "" || u.Host == "" {
		scheme := u.Scheme
		host := u.Host

		if scheme == "" {
			if w.req.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}

		if host == "" {
			host = w.req.Host
		}

		w.cachedURL = &url.URL{
			Scheme:      scheme,
			Host:        host,
			Path:        u.Path,
			RawPath:     u.RawPath,
			RawQuery:    u.RawQuery,
			Fragment:    u.Fragment,
			RawFragment: u.RawFragment,
		}
		return w.cachedURL, nil
	}

	w.cachedURL = u
	return u, nil
}

func (w *requestWrapper) StatusCode() (int, error) {
	return 0, errors.New("StatusCode() called on HTTP request (only valid for responses)")
}

func (w *requestWrapper) HeaderValues(name string) []string {
	// Use http.CanonicalHeaderKey for case-insensitive lookup
	return w.req.Header[http.CanonicalHeaderKey(name)]
}

func (w *requestWrapper) TrailerValues(name string) []string {
	// Use http.CanonicalHeaderKey for case-insensitive lookup
	return w.req.Trailer[http.CanonicalHeaderKey(name)]
}

func (w *requestWrapper) RelatedRequest() HTTPMessage {
	// Requests don't have related requests
	return nil
}

// responseWrapper adapts *http.Response to the HTTPMessage interface.
type responseWrapper struct {
	resp       *http.Response
	relatedReq HTTPMessage
}

// WrapResponse adapts a standard *http.Response to the HTTPMessage interface.
//
// The relatedReq parameter is optional and should be provided when the response
// signature needs to access request components via the 'req' parameter.
//
// Example:
//
//	resp := &http.Response{
//	    StatusCode: 200,
//	    Header: http.Header{
//	        "Content-Type": []string{"application/json"},
//	    },
//	}
//
//	message := base.WrapResponse(resp, base.WrapRequest(originalReq))
//	signatureBase, err := base.Build(message, components, params)
func WrapResponse(resp *http.Response, relatedReq *http.Request) HTTPMessage {
	var wrappedReq HTTPMessage
	if relatedReq != nil {
		wrappedReq = WrapRequest(relatedReq)
	}

	return &responseWrapper{
		resp:       resp,
		relatedReq: wrappedReq,
	}
}

func (w *responseWrapper) IsRequest() bool {
	return false
}

func (w *responseWrapper) IsResponse() bool {
	return true
}

func (w *responseWrapper) Method() (string, error) {
	return "", errors.New("method Method() called on HTTP response (only valid for requests)")
}

func (w *responseWrapper) URL() (*url.URL, error) {
	return nil, errors.New("method URL() called on HTTP response (only valid for requests)")
}

func (w *responseWrapper) StatusCode() (int, error) {
	return w.resp.StatusCode, nil
}

func (w *responseWrapper) HeaderValues(name string) []string {
	// Use http.CanonicalHeaderKey for case-insensitive lookup
	return w.resp.Header[http.CanonicalHeaderKey(name)]
}

func (w *responseWrapper) TrailerValues(name string) []string {
	// Use http.CanonicalHeaderKey for case-insensitive lookup
	return w.resp.Trailer[http.CanonicalHeaderKey(name)]
}

func (w *responseWrapper) RelatedRequest() HTTPMessage {
	return w.relatedReq
}
