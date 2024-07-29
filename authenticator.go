package l402

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type Rejection error

type RecoverableRejection interface {
	SignalRecovery(http.Header)
	error
}

type authenticator struct {
	macaroonMinter MacaroonMinter
	errorHandler   http.Handler
}

func Authenticator(minter MacaroonMinter, errorHandler http.Handler) authenticator {
	return authenticator{
		macaroonMinter: minter,
		errorHandler:   errorHandler,
	}
}

func (a authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rejection := context.Cause(r.Context())

	var recoverableRejection RecoverableRejection
	if errors.As(rejection, &recoverableRejection) {
		// Rejecting access to an API resourse triggers a re-authentication opportunity
		// The rejection way be reverted without the need for a new payment
		// For that, we use the response header to signal the client what action can be taken
		// Recovery can usually happen by removing some of the macaroon's caveats
		recoverableRejection.SignalRecovery(w.Header())
	} else if rejection == nil {
		rejection = ErrAuthenticationRequired
	}

	macaroonBase64, invoice, err := a.macaroonMinter.MintWithInvoice(r)
	if err != nil {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(fmt.Errorf("%w: %w", ErrFailedMacaroonMinting, err))
		a.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// TODO: Maybe support BOLT 12/LNURL: L402 macaroon="%s", offer="%s"
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`L402 macaroon="%s", invoice="%s"`, macaroonBase64, invoice))
	http.Error(w, rejection.Error(), http.StatusPaymentRequired)
}
