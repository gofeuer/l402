package l402

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"

	macaroon "gopkg.in/macaroon.v2"
)

type Challenge interface {
	String() string
}

type MacaroonMinter interface {
	MintWithChallenge(*http.Request) (string, Challenge, error)
}

type Rejection error

type AccessAuthority interface {
	ApproveAccess(*http.Request, macaroon.Slice, Hash) Rejection
}

type proxy struct {
	authenticator   http.Handler
	accessAuthority AccessAuthority
	apiHandler      http.Handler
	errorHandler    http.Handler
}

func Proxy(minter MacaroonMinter, authority AccessAuthority, options ...option) func(http.Handler) http.Handler {
	p := proxy{
		accessAuthority: authority,
		errorHandler:    http.HandlerFunc(DefaultErrorHandler),
	}

	// Overwrite default values.
	for _, option := range options {
		option(&p)
	}

	if p.authenticator == nil {
		p.authenticator = Authenticator(minter, p.errorHandler)
	}

	// Return as a middleware.
	return func(apiHandler http.Handler) http.Handler {
		p.apiHandler = apiHandler
		return &p
	}
}

type ContextKey string

const KeyMacaroon ContextKey = "proxy_macaroon"

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	macaroonBase64, preimageHash, found := getL402AuthorizationHeader(r)
	if !found {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(ErrPaymentRequired)
		p.authenticator.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	macaroons, err := UnmarshalMacaroons(macaroonBase64)
	if err != nil {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(fmt.Errorf("%w: %w", ErrInvalidMacaroon, err))
		p.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// Check if macaroon is singed by a valid key and that it grants access to the requested resource.
	if rejection := p.accessAuthority.ApproveAccess(r, macaroons, preimageHash); rejection != nil {
		// The presented macaroon might not have been singed properly or was revoked,
		// or the presented macaroon is valid but doesn't grant access to this resource.
		// So we give the client the option to re-authenticate with a proper macaroon.
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(rejection)
		p.authenticator.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// At this point the request is valid, so we proxy the API call.
	ctx := context.WithValue(r.Context(), KeyMacaroon, macaroons)
	p.apiHandler.ServeHTTP(w, r.WithContext(ctx))
}

const (
	hexSize             = HashSize * 2
	expectedMatches     = 3 // L402 (\S+):([a-f0-9]{64}) -> [authorizationHeader, macaroonBase64, preimageHex]
	macaroonBase64Index = 1
	preimageHexIndex    = 2
)

var authorizationMatcher = regexp.MustCompile(fmt.Sprintf(`L402 (\S+):([a-f0-9]{%d})`, hexSize))

func getL402AuthorizationHeader(r *http.Request) (string, Hash, bool) {
	var preimageHash Hash

	for _, authorizationHeader := range r.Header.Values("Authorization") {
		matches := authorizationMatcher.FindStringSubmatch(authorizationHeader)
		if len(matches) == expectedMatches {
			macaroonBase64 := matches[macaroonBase64Index]
			preimageHex := matches[preimageHexIndex]

			// preimageHex is guaranteed by authorizationMatcher to be a string of 64 hexadecimal characters.
			hex.Decode(preimageHash[:], []byte(preimageHex)) //nolint:errcheck
			preimageHash = sha256.Sum256(preimageHash[:])

			return macaroonBase64, preimageHash, true
		}
	}
	return "", Hash{}, false
}

type option func(*proxy)

func WithAuthenticator(authenticator http.Handler) option {
	return func(p *proxy) {
		p.authenticator = authenticator
	}
}

func WithErrorHandler(errorHandler http.Handler) option {
	return func(p *proxy) {
		p.errorHandler = errorHandler
	}
}
