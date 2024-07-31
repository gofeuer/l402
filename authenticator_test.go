package l402

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticator_ServeHTTP(t *testing.T) {
	tests := map[string]struct {
		rejection                      error
		mintWithInvoice                func(r *http.Request) (string, string, error)
		expectedError                  spyHandler
		expectedHeaderAuthenticate     string
		expectedHeaderAuthenticateInfo string
		expectedResponse               string
		expectedResponseStatus         int
	}{
		"failed minting": {
			mintWithInvoice: func(r *http.Request) (string, string, error) {
				return "", "", errors.New("some error")
			},
			expectedError: spyHandler{
				called:          true,
				cancelCause:     fmt.Errorf("%w: %w", ErrFailedMacaroonMinting, errors.New("some error")),
				replyStatusCode: http.StatusInternalServerError,
			},
			expectedResponseStatus: http.StatusInternalServerError,
		},
		"unrecoverable rejection": {
			rejection: errors.New("some unrecoverable error"),
			mintWithInvoice: func(r *http.Request) (string, string, error) {
				return "macaroonBase64", "invoice", nil
			},
			expectedHeaderAuthenticate: `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedResponse:           `some unrecoverable error`,
			expectedResponseStatus:     http.StatusPaymentRequired,
		},
		"recoverable rejection": {
			rejection: fakeRecoverableRejection(`rocovery="tier-upgrade" minimum-tier="premium-plus"`),
			mintWithInvoice: func(r *http.Request) (string, string, error) {
				return "macaroonBase64", "invoice", nil
			},
			expectedHeaderAuthenticate:     `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedHeaderAuthenticateInfo: `rocovery="tier-upgrade" minimum-tier="premium-plus"`,
			expectedResponse:               `payment required`,
			expectedResponseStatus:         http.StatusPaymentRequired,
		},
		"simple payment required": {
			mintWithInvoice: func(r *http.Request) (string, string, error) {
				return "macaroonBase64", "invoice", nil
			},
			expectedHeaderAuthenticate: `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedResponse:           `payment required`,
			expectedResponseStatus:     http.StatusPaymentRequired,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			minter := mockMinter{test.mintWithInvoice}
			errorHandler := spyHandler{replyStatusCode: test.expectedError.replyStatusCode}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/some_proctected_resource", nil)
			if test.rejection != nil {
				ctx, cancelCause := context.WithCancelCause(r.Context())
				cancelCause(test.rejection)
				r = r.WithContext(ctx)
			}

			Authenticator(minter, &errorHandler).ServeHTTP(w, r)

			response := w.Result()

			if errorHandler.called != test.expectedError.called {
				t.Errorf("expected: %v but got: %v", test.expectedError.called, errorHandler.called)
			}

			if !(errors.Is(errorHandler.cancelCause, test.expectedError.cancelCause) ||
				errorHandler.cancelCause.Error() == test.expectedError.cancelCause.Error()) {
				t.Errorf("expected: %s but got: %s", test.expectedError.cancelCause.Error(), errorHandler.cancelCause.Error())
			}

			if headerAuthenticate := response.Header.Get("WWW-Authenticate"); headerAuthenticate != test.expectedHeaderAuthenticate {
				t.Errorf("expected: %s but got: %s", test.expectedHeaderAuthenticate, headerAuthenticate)
			}

			if body, _ := io.ReadAll(response.Body); strings.TrimSpace(string(body)) != test.expectedResponse {
				t.Errorf("expected: %s but got: %s", test.expectedResponse, body)
			}
			response.Body.Close()

			if response.StatusCode != test.expectedResponseStatus {
				t.Errorf("expected: %d but got: %d", test.expectedResponseStatus, response.StatusCode)
			}

			if headerAuthenticateInfo := response.Header.Get("Authentication-Info"); headerAuthenticateInfo != test.expectedHeaderAuthenticateInfo {
				t.Errorf("expected: %s but got: %s", test.expectedHeaderAuthenticateInfo, headerAuthenticateInfo)
			}
		})
	}
}

type mockMinter struct {
	mintWithInvoice func(*http.Request) (string, string, error)
}

func (m mockMinter) MintWithInvoice(r *http.Request) (string, string, error) {
	return m.mintWithInvoice(r)
}

type spyHandler struct {
	called          bool
	cancelCause     error
	replyStatusCode int
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called = true
	s.cancelCause = context.Cause(r.Context())
	if s.replyStatusCode != 0 {
		w.WriteHeader(s.replyStatusCode)
	}
}

type fakeRecoverableRejection string

func (f fakeRecoverableRejection) Error() string {
	return ErrPaymentRequired.Error()
}

func (f fakeRecoverableRejection) AdviseRecovery(header http.Header) {
	header.Add("Authentication-Info", string(f))
}
