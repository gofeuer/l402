package l402

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	macaroon "gopkg.in/macaroon.v2"
)

func TestProxy_ServeHTTP(t *testing.T) {
	tests := map[string]struct {
		authorizationHeader    string
		approveAccess          func(*http.Request, map[Identifier]*macaroon.Macaroon) Rejection
		expectedAuthenticator  spyHandler
		apiHandler             spyHandler
		expectedError          spyHandler
		expectedResponseStatus int
	}{
		"no authorization": {
			expectedAuthenticator: spyHandler{
				called:          true,
				cancelCause:     ErrPaymentRequired,
				replyStatusCode: http.StatusPaymentRequired,
			},
			expectedResponseStatus: http.StatusPaymentRequired,
		},
		"defective macaroon": {
			authorizationHeader: "L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==:79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedError: spyHandler{
				called:          true,
				cancelCause:     ErrInvalidMacaroon,
				replyStatusCode: http.StatusBadRequest,
			},
			expectedResponseStatus: http.StatusBadRequest,
		},
		"invalid preimage": {
			authorizationHeader: "L402 AgJCAABmaHqt+GK9d2yPwYuOn44gCJcUhW7iM7OQKlkdDV8pJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGIPYUpoJjGXj6TR3qNyibnh+n2R1Dj5HEt5dV4GfbU0jX:0000000000000000000000000000000000000000000000000000000000000001",
			expectedError: spyHandler{
				called:          true,
				cancelCause:     ErrInvalidPreimage,
				replyStatusCode: http.StatusBadRequest,
			},
			expectedResponseStatus: http.StatusBadRequest,
		},
		"rejected access": {
			authorizationHeader: "L402 AgJCAABmaHqt+GK9d2yPwYuOn44gCJcUhW7iM7OQKlkdDV8pJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGIPYUpoJjGXj6TR3qNyibnh+n2R1Dj5HEt5dV4GfbU0jX:0000000000000000000000000000000000000000000000000000000000000000",
			approveAccess: func(*http.Request, map[Identifier]*macaroon.Macaroon) Rejection {
				return ErrPaymentRequired
			},
			expectedAuthenticator: spyHandler{
				called:          true,
				cancelCause:     ErrPaymentRequired,
				replyStatusCode: http.StatusPaymentRequired,
			},
			expectedResponseStatus: http.StatusPaymentRequired,
		},
		"success": {
			authorizationHeader: "L402 AgJCAABmaHqt+GK9d2yPwYuOn44gCJcUhW7iM7OQKlkdDV8pJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGIPYUpoJjGXj6TR3qNyibnh+n2R1Dj5HEt5dV4GfbU0jX:0000000000000000000000000000000000000000000000000000000000000000",
			approveAccess: func(*http.Request, map[Identifier]*macaroon.Macaroon) Rejection {
				return nil // access approved
			},
			apiHandler: spyHandler{
				called: true,
			},
			expectedResponseStatus: http.StatusOK,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authenticator := spyHandler{replyStatusCode: test.expectedAuthenticator.replyStatusCode}
			accessAuthority := mockAccessAuthority{test.approveAccess}
			apiHandler := spyHandler{replyStatusCode: test.apiHandler.replyStatusCode}
			errorHandler := spyHandler{replyStatusCode: test.expectedError.replyStatusCode}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/some_proctected_resource", nil)
			r.Header.Set("Authorization", test.authorizationHeader)

			Proxy(nil, accessAuthority, WithAuthenticator(&authenticator), WithErrorHandler(&errorHandler))(&apiHandler).ServeHTTP(w, r)

			response := w.Result()

			if authenticator.called != test.expectedAuthenticator.called {
				t.Errorf("expected: %v but got: %v", test.expectedAuthenticator.called, authenticator.called)
			}

			if errorHandler.called != test.expectedError.called {
				t.Errorf("expected: %v but got: %v", test.expectedError.called, errorHandler.called)
			}

			if !(errors.Is(errorHandler.cancelCause, test.expectedError.cancelCause) ||
				errorHandler.cancelCause.Error() == test.expectedError.cancelCause.Error()) {
				t.Errorf("expected: %s but got: %s", test.expectedError.cancelCause.Error(), errorHandler.cancelCause.Error())
			}

			if response.StatusCode != test.expectedResponseStatus {
				t.Errorf("expected: %d but got: %d", test.expectedResponseStatus, response.StatusCode)
			}
		})
	}
}

func TestGetL402AuthorizationHeader(t *testing.T) {
	tests := map[string]struct {
		headerValue      string
		expectedMacaroon string
		expectedPreimage string
		expectedFound    bool
	}{
		"nou auth": {
			expectedFound: false,
		},
		"other auth": {
			headerValue:   "Basic AGIAJEemVQUTEa0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound: false,
		},
		"invalid 402": {
			headerValue:   "L402 :79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound: false,
		},
		"invalid 402 space": {
			headerValue:   "L402  :79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound: false,
		},
		"invalid 402 string space": {
			headerValue:   "L402 abc d:79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound: false,
		},
		"invalid 402 preimage": {
			headerValue:   "L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==:79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad8121740",
			expectedFound: false,
		},
		"success": {
			headerValue:      "L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==:79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedMacaroon: "AGIAJEemVQUTEyNCR0exk7ek90Cg==",
			expectedPreimage: "79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound:    true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := http.Request{Header: make(http.Header)}
			r.Header.Set("Authorization", test.headerValue)

			macaroonBase64, preimageHash, found := getL402AuthorizationHeader(&r)

			if found != test.expectedFound {
				t.Fatalf("expected: %v but got: %v", test.expectedFound, found)
			}

			if macaroonBase64 != test.expectedMacaroon {
				t.Errorf("expected: %s but got: %s", test.expectedMacaroon, macaroonBase64)
			}

			var expectedPreimageHash Hash
			if test.expectedPreimage != "" {
				hex.Decode(expectedPreimageHash[:], []byte(test.expectedPreimage))
				expectedPreimageHash = sha256.Sum256(expectedPreimageHash[:])
			}

			if preimageHash != expectedPreimageHash {
				t.Errorf("expected: %v but got: %v", preimageHash, expectedPreimageHash)
			}
		})
	}
}

func TestValidatePreimage(t *testing.T) {
	tests := map[string]struct {
		preimageHash   Hash
		expectedResult bool
	}{
		"valid preimage": {
			preimageHash: Hash{
				166, 18, 134, 107, 7, 192, 14, 53, 235, 54, 169, 100, 101, 177, 74, 170,
				6, 147, 124, 244, 193, 53, 90, 53, 242, 92, 235, 25, 179, 10, 56, 21,
			},
			expectedResult: true,
		},
		"invalid preimage": {
			preimageHash: Hash{
				1, 8, 134, 107, 7, 192, 14, 53, 235, 54, 169, 100, 101, 177, 74, 10,
				6, 147, 124, 244, 193, 53, 90, 53, 242, 92, 235, 25, 179, 10, 6, 20,
			},
			expectedResult: false,
		},
	}

	paymentHash := Hash{
		166, 18, 134, 107, 7, 192, 14, 53, 235, 54, 169, 100, 101, 177, 74, 170,
		6, 147, 124, 244, 193, 53, 90, 53, 242, 92, 235, 25, 179, 10, 56, 21,
	}

	macaroons := make(map[Identifier]*macaroon.Macaroon)
	macaroons[Identifier{ID: ID{1}, PaymentHash: paymentHash}] = &macaroon.Macaroon{}
	macaroons[Identifier{ID: ID{2}, PaymentHash: paymentHash}] = &macaroon.Macaroon{}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			valid := validatePreimage(macaroons, test.preimageHash)

			if valid != test.expectedResult {
				t.Errorf("expected: %v but got: %v", test.expectedResult, valid)
			}
		})
	}
}

type mockAccessAuthority struct {
	approveAccess func(*http.Request, map[Identifier]*macaroon.Macaroon) Rejection
}

func (a mockAccessAuthority) ApproveAccess(r *http.Request, m map[Identifier]*macaroon.Macaroon) Rejection {
	return a.approveAccess(r, m)
}
