package l402

import (
	"net/http"

	macaroon "gopkg.in/macaroon.v2"
)

type MacaroonMinter interface {
	MintWithInvoice(*http.Request) (string, string, error)
}

type AccessAuthority interface {
	ApproveAccess(*http.Request, macaroon.Macaroon, Identifier) Rejection
}

type proxy struct {
	authenticator   http.Handler
	accessAuthority AccessAuthority
	apiHandler      http.Handler
	errorHandler    http.HandlerFunc
}

type middleware func(http.Handler) http.Handler

func Proxy(minter MacaroonMinter, authority AccessAuthority, options ...option) middleware {
	p := proxy{
		accessAuthority: authority,
		errorHandler:    DefaultErrorHandler,
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

type option func(*proxy)

func WithAuthenticator(authenticator http.Handler) option {
	return func(p *proxy) {
		p.authenticator = authenticator
	}
}

func WithErrorHandler(errorrHandler http.HandlerFunc) option {
	return func(p *proxy) {
		p.errorHandler = errorrHandler
	}
}