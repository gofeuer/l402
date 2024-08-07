package l402

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrInvalidMacaroon       = errors.New("invalid macaroon")
	ErrInvalidPreimage       = errors.New("invalid preimage")
	ErrFailedInvoiceRequest  = errors.New("failed invoice request")
	ErrFailedMacaroonMinting = errors.New("failed macaroon minting")
	ErrPaymentRequired       = errors.New("payment required")
	ErrUnknownVersion        = errors.New("unknown L402 version")
	ErrEmptyMacaroonData     = errors.New("empty macaroon data")
)

func DefaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	err := context.Cause(r.Context())
	switch {
	case errors.Is(err, ErrInvalidMacaroon), errors.Is(err, ErrInvalidPreimage):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
