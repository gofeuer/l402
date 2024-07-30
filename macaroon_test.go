package l402

import (
	"bytes"
	"errors"
	"testing"

	macaroon "gopkg.in/macaroon.v2"
)

func TestMarshalMacaroons(t *testing.T) {
	macV1, _ := macaroon.New(nil, nil, "", macaroon.V1)
	macV2, _ := macaroon.New(nil, nil, "", macaroon.V2)

	tests := map[string]struct {
		macaroons              []macaroon.Macaroon
		expectedMacaroonBase64 string
		expectedError          error
	}{
		"no macaroons": {
			expectedError: errors.New("can't marshal empty macaroon slice"),
		},
		"one macaroon": {
			macaroons: []macaroon.Macaroon{
				*macV1,
			},
			expectedMacaroonBase64: "MDAwZWxvY2F0aW9uIAowMDEwaWRlbnRpZmllciAKMDAyZnNpZ25hdHVyZSCPtT9UwdGWx8khvYJlWY9BhJu6JUG3in2Ef49M+/Oukgo=",
		},
		"many macaroons": {
			macaroons: []macaroon.Macaroon{
				*macV2,
				*macV2,
			},
			expectedMacaroonBase64: "AgIAAAAGII+1P1TB0ZbHySG9gmVZj0GEm7olQbeKfYR/j0z7866S,AgIAAAAGII+1P1TB0ZbHySG9gmVZj0GEm7olQbeKfYR/j0z7866S",
		},
		"defective macaroon": {
			macaroons: []macaroon.Macaroon{
				*macV1,
				*macV2,
				{},
				*macV2,
			},
			expectedError: errors.New("bad macaroon version v0: index: 2"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			macaroonBase64, err := MarshalMacaroons(test.macaroons)

			if !(errors.Is(err, test.expectedError) || err.Error() == test.expectedError.Error()) {
				t.Errorf("expected: %v but got: %v", test.expectedError, err)
			}

			if macaroonBase64 != test.expectedMacaroonBase64 {
				t.Errorf("expected: %v but got: %v", test.expectedMacaroonBase64, macaroonBase64)
			}
		})
	}
}

func TestMarchalIdentifier(t *testing.T) {
	tests := map[string]struct {
		version            uint16
		paymentHash        Hash
		id                 ID
		expectedMacaroonId []byte
		expectedErr        error
	}{
		"invalid version": {
			version:     1,
			expectedErr: ErrUnknownVersion,
		},
		"success": {
			paymentHash: [32]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			id: [32]byte{
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedMacaroonId: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			identifier := Identifier{
				Version:     test.version,
				PaymentHash: test.paymentHash,
				Id:          test.id,
			}

			macaroonID, err := MarchalIdentifier(identifier)

			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected: %v but got: %v", test.expectedErr, err)
			}

			if !bytes.Equal(macaroonID, test.expectedMacaroonId) {
				t.Errorf("expected: %s but got: %s", test.expectedMacaroonId, macaroonID)
			}
		})
	}
}

func TestUnmarshalIdentifier(t *testing.T) {
	tests := map[string]struct {
		macaroonID          []byte
		expectedPaymentHash Hash
		expectedId          ID
		expectedErr         error
	}{
		"invalid version": {
			macaroonID:  []byte{0, 2},
			expectedErr: ErrUnknownVersion,
		},
		"success": {
			macaroonID: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedPaymentHash: [32]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			expectedId: [32]byte{
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			identifier, err := UnmarshalIdentifier(test.macaroonID)

			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected: %v but got: %v", test.expectedErr, err)
			}

			if identifier.PaymentHash != test.expectedPaymentHash {
				t.Errorf("expected: %s but got: %s", test.expectedPaymentHash, identifier.PaymentHash)
			}

			if identifier.Id != test.expectedId {
				t.Errorf("expected:: %s but got: %s", test.expectedId, identifier.Id)
			}
		})
	}
}
