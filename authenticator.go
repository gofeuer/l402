package l402

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type RecoverableRejection interface {
	Rejection
	AdviseRecovery(http.Header)
}

type challenge string

type Invoice challenge

func (i Invoice) String() string {
	return fmt.Sprintf(`invoice="%s"`, string(i))
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
	// Ask the minter to give us a macaroon and a challenge (a lightning invoice).
	macaroonBase64, challenge, err := a.macaroonMinter.MintWithChallenge(r)
	if err != nil {
		ctx, cancelCause := context.WithCancelCause(r.Context())
		cancelCause(err)
		a.errorHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// Check what triggered this authentication request
	rejection := context.Cause(r.Context())
	var recoverableRejection RecoverableRejection
	if errors.As(rejection, &recoverableRejection) {
		// Use the response header to advise the client on how retry without the need for a new payment.
		// The client usually does that by retrying with a macaroon with less restrictive caveats.
		recoverableRejection.AdviseRecovery(w.Header())
	} else if rejection == nil {
		rejection = ErrPaymentRequired
	}

	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`L402 macaroon="%s", %s`, macaroonBase64, challenge))
	http.Error(w, rejection.Error(), http.StatusPaymentRequired)
}
