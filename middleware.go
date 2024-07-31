package l402

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
)

type ContextKey string

const KeyMacaroon ContextKey = "proxy_macaroon"

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	macaroonBase64, preimageHex, found := getL402AuthorizationHeader(r)
	if !found {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(ErrPaymentRequired)
		p.authenticator.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	macaroon, identifier, err := UnmarshalMacaroon(macaroonBase64)
	if err != nil {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(fmt.Errorf("%w: %w", ErrInvalidMacaroon, err))
		p.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	ctx := context.WithValue(r.Context(), KeyMacaroon, macaroon)

	if valid := validatePreimage(preimageHex, identifier.PaymentHash); !valid {
		ctx, cancelCause := context.WithCancelCause(ctx)
		cancelCause(ErrInvalidPreimage)
		p.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// Check if macarron is singed by a valid key and that it grants access to the requested resource
	if rejection := p.accessAuthority.ApproveAccess(r, macaroon, identifier); rejection != nil {
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

const hexBlockSize = BlockSize * 2

var authorizationMatcher = regexp.MustCompile(fmt.Sprintf("L402 (.*?):([a-f0-9]{%d})", hexBlockSize))

func getL402AuthorizationHeader(r *http.Request) (string, string, bool) {
	for _, v := range r.Header.Values("Authorization") {
		if matches := authorizationMatcher.FindStringSubmatch(v); len(matches) == 3 {
			return matches[1], matches[2], true
		}
	}
	return "", "", false
}

func validatePreimage(preimageHex string, paymentHash Hash) bool {
	var preimage Hash
	hex.Decode(preimage[:], []byte(preimageHex))
	preimage = sha256.Sum256(preimage[:])
	return preimage == paymentHash
}
