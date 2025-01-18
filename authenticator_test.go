package l402

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticator_ServeHTTP(t *testing.T) {
	tests := map[string]struct {
		rejection                      error
		mintWithChallenge              func(*http.Request) (string, Challenge, error)
		expectedError                  spyHandler
		expectedHeaderAuthenticate     string
		expectedHeaderAuthenticateInfo string
		expectedResponse               string
		expectedResponseStatus         int
	}{
		"failed minting": {
			mintWithChallenge: func(r *http.Request) (string, Challenge, error) {
				return "", nil, ErrFailedMacaroonMinting
			},
			expectedError: spyHandler{
				called:          true,
				cancelCause:     ErrFailedMacaroonMinting,
				replyStatusCode: http.StatusInternalServerError,
			},
			expectedResponseStatus: http.StatusInternalServerError,
		},
		"failed invoice request": {
			mintWithChallenge: func(r *http.Request) (string, Challenge, error) {
				return "", nil, ErrFailedInvoiceRequest
			},
			expectedError: spyHandler{
				called:          true,
				cancelCause:     ErrFailedInvoiceRequest,
				replyStatusCode: http.StatusInternalServerError,
			},
			expectedResponseStatus: http.StatusInternalServerError,
		},
		"unrecoverable rejection": {
			rejection: errors.New("some unrecoverable error"),
			mintWithChallenge: func(r *http.Request) (string, Challenge, error) {
				return "macaroonBase64", Invoice("invoice"), nil
			},
			expectedHeaderAuthenticate: `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedResponse:           `some unrecoverable error`,
			expectedResponseStatus:     http.StatusPaymentRequired,
		},
		"recoverable rejection": {
			rejection: fakeRecoverableRejection(`recovery="tier-upgrade" minimum-tier="premium-plus"`),
			mintWithChallenge: func(r *http.Request) (string, Challenge, error) {
				return "macaroonBase64", Invoice("invoice"), nil
			},
			expectedHeaderAuthenticate:     `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedHeaderAuthenticateInfo: `recovery="tier-upgrade" minimum-tier="premium-plus"`,
			expectedResponse:               `payment required`,
			expectedResponseStatus:         http.StatusPaymentRequired,
		},
		"simple payment required": {
			mintWithChallenge: func(r *http.Request) (string, Challenge, error) {
				return "macaroonBase64", Invoice("invoice"), nil
			},
			expectedHeaderAuthenticate: `L402 macaroon="macaroonBase64", invoice="invoice"`,
			expectedResponse:           `payment required`,
			expectedResponseStatus:     http.StatusPaymentRequired,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			minter := mockMinter{test.mintWithChallenge}
			errorHandler := spyHandler{replyStatusCode: test.expectedError.replyStatusCode}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/some_protected_resource", nil)
			if test.rejection != nil {
				ctx, cancelCause := context.WithCancelCause(r.Context())
				cancelCause(test.rejection)
				r = r.WithContext(ctx)
			}

			Authenticator(minter, &errorHandler).ServeHTTP(w, r)

			response := w.Result()
			body, _ := io.ReadAll(response.Body)
			defer response.Body.Close()
			responseBody := strings.TrimSpace(string(body))

			if errorHandler.called != test.expectedError.called {
				t.Errorf("expected: %v but got: %v", test.expectedError.called, errorHandler.called)
			}

			if !errors.Is(errorHandler.cancelCause, test.expectedError.cancelCause) {
				t.Errorf("expected: %s but got: %s", test.expectedError.cancelCause, errorHandler.cancelCause)
			}

			headerAuthenticate := response.Header.Get("WWW-Authenticate")
			if headerAuthenticate != test.expectedHeaderAuthenticate {
				t.Errorf("expected: %s but got: %s", test.expectedHeaderAuthenticate, headerAuthenticate)
			}

			if responseBody != test.expectedResponse {
				t.Errorf("expected: %s but got: %s", test.expectedResponse, responseBody)
			}

			if response.StatusCode != test.expectedResponseStatus {
				t.Errorf("expected: %d but got: %d", test.expectedResponseStatus, response.StatusCode)
			}

			headerAuthenticateInfo := response.Header.Get("Authentication-Info")
			if headerAuthenticateInfo != test.expectedHeaderAuthenticateInfo {
				t.Errorf("expected: %s but got: %s", test.expectedHeaderAuthenticateInfo, headerAuthenticateInfo)
			}
		})
	}
}

type mockMinter struct {
	mintWithChallenge func(*http.Request) (string, Challenge, error)
}

func (m mockMinter) MintWithChallenge(r *http.Request) (string, Challenge, error) {
	return m.mintWithChallenge(r)
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
