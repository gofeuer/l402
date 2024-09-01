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

type MacaroonMinter interface {
	MintWithChallenge(*http.Request) (string, Challenge, error)
}

type AccessAuthority interface {
	ApproveAccess(*http.Request, map[Identifier]*macaroon.Macaroon) Rejection
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

	// Overwrite default values
	for _, option := range options {
		option(&p)
	}

	if p.authenticator == nil {
		p.authenticator = Authenticator(minter, p.errorHandler)
	}

	// Return as a middleware
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

	ctx := context.WithValue(r.Context(), KeyMacaroon, macaroons)

	if valid := validatePreimage(macaroons, preimageHash); !valid {
		ctx, cancelCause := context.WithCancelCause(ctx)
		cancelCause(ErrInvalidPreimage)
		p.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// Check if macarron is singed by a valid key and that it grants access to the requested resource
	if rejection := p.accessAuthority.ApproveAccess(r, macaroons); rejection != nil {
		// The presented macaroon might not have been singed properlly or was revoked
		// Or the presented macaroon is valid but doesn't grant access to this resource
		// So we give the client the option to re-authenticate with a proper macaroon
		ctx, cancelCause := context.WithCancelCause(ctx)
		cancelCause(rejection)
		p.authenticator.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// At this point the request is valid, so we proxy the API call
	p.apiHandler.ServeHTTP(w, r.WithContext(ctx))
}

const (
	hexBlockSize        = BlockSize * 2
	expectedMatches     = 3 // L402 (\S+):([a-f0-9]{64}) -> [the header, macaroonBase64, preimageHex]
	macaroonBase64Index = 1
	preimageHexIndex    = 2
)

var authorizationMatcher = regexp.MustCompile(fmt.Sprintf(`L402 (\S+):([a-f0-9]{%d})`, hexBlockSize))

func getL402AuthorizationHeader(r *http.Request) (string, Hash, bool) {
	var preimageHash Hash

	for _, v := range r.Header.Values("Authorization") {
		if matches := authorizationMatcher.FindStringSubmatch(v); len(matches) == expectedMatches {
			macaroonBase64 := matches[macaroonBase64Index]
			preimageHex := matches[preimageHexIndex]

			// preimageHex is guaranteed by authorizationMatcher to be 64 hexadecimal characters
			hex.Decode(preimageHash[:], []byte(preimageHex)) //nolint:errcheck
			preimageHash = sha256.Sum256(preimageHash[:])

			return macaroonBase64, preimageHash, true
		}
	}
	return "", Hash{}, false
}

func validatePreimage(macaroons map[Identifier]*macaroon.Macaroon, preimageHash Hash) bool {
	for identifier := range macaroons {
		if identifier.PaymentHash != preimageHash {
			return false
		}
	}
	return true
}

type option func(*proxy)

func WithAuthenticator(authenticator http.Handler) option {
	return func(p *proxy) {
		p.authenticator = authenticator
	}
}

func WithErrorHandler(errorrHandler http.Handler) option {
	return func(p *proxy) {
		p.errorHandler = errorrHandler
	}
}
