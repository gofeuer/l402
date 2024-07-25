package l402

import (
	"net/http"
	"testing"
)

func TestGetL402AuthorizationHeader(t *testing.T) {
	tests := map[string]struct {
		headerValue      string
		expectedMacaroon string
		expectedPreimage string
		expectedFound    bool
	}{
		"success": {
			headerValue:      "L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==:79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedMacaroon: "AGIAJEemVQUTEyNCR0exk7ek90Cg==",
			expectedPreimage: "79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound:    true,
		},
		"invalid 402": {
			headerValue:   "L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==",
			expectedFound: false,
		},
		"other auth": {
			headerValue:   "Basic AGIAJEemVQUTEa0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedFound: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := http.Request{
				Header: make(http.Header),
			}
			r.Header.Set("Authorization", test.headerValue)

			macaroonBase64, preimageHex, found := getL402AuthorizationHeader(&r)

			if macaroonBase64 != test.expectedMacaroon {
				t.Errorf("test failed: %s, expected %s but got %s", name, test.expectedMacaroon, macaroonBase64)
			}

			if preimageHex != test.expectedPreimage {
				t.Errorf("test failed: %s, expected %s but got %s", name, test.expectedPreimage, preimageHex)
			}

			if found != test.expectedFound {
				t.Errorf("test failed: %s, expected %v but got %v", name, test.expectedFound, found)
			}
		})
	}
}

func TestValidatePreimage(t *testing.T) {
	tests := map[string]struct {
		preimageHex    string
		expectedResult bool
	}{
		"valid preimage": {
			preimageHex:    "79852a0791225dee00be0a6cf31a1619782c21d35995e118bfc74ad812174035",
			expectedResult: true,
		},
		"invalid preimage": {
			preimageHex:    "invalidpreimagehex",
			expectedResult: false,
		},
	}

	paymentHash := Hash{
		166, 18, 134, 107, 7, 192, 14, 53, 235, 54, 169, 100, 101, 177, 74, 170,
		6, 147, 124, 244, 193, 53, 90, 53, 242, 92, 235, 25, 179, 10, 56, 21,
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			valid := validatePreimage(test.preimageHex, paymentHash)

			if valid != test.expectedResult {
				t.Errorf("test failed: %s", name)
			}
		})
	}
}
